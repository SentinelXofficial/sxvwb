// Package prime auto-extracts structured data from responses: database
// names from SQL errors, file paths from LFI leaks, IAM credentials from
// SSRF metadata, token values from JWT headers — turning raw response text
// into actionable intelligence.
package prime

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// ── Types ────────────────────────────────────────────────────────────────

// Extract holds everything that was auto-extracted from a response.
type Extract struct {
	DBName      string   `json:"db_name,omitempty"`
	DBVersion   string   `json:"db_version,omitempty"`
	DBTables    []string `json:"db_tables,omitempty"`
	Users       []string `json:"users,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	Tokens      []string `json:"tokens,omitempty"`
	Passwords   []string `json:"passwords,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Filepaths   []string `json:"filepaths,omitempty"`
	APIKeys     []string `json:"api_keys,omitempty"`
	AWSCreds    []string `json:"aws_creds,omitempty"`
	JWTSecrets  []string `json:"jwt_secrets,omitempty"`
	EnvVars     []string `json:"env_vars,omitempty"`
	SSHKeys     []string `json:"ssh_keys,omitempty"`
	SourceCode  []string `json:"source_code,omitempty"`
}

// ── Extractors ───────────────────────────────────────────────────────────

// Pull tries every extractor on the body and returns everything found.
func Pull(body string) *Extract {
	e := &Extract{}

	e.Emails = extractEmails(body)
	e.Tokens = extractTokens(body)
	e.Passwords = extractPasswords(body)
	e.IPs = extractIPs(body)
	e.Filepaths = extractFilepaths(body)
	e.APIKeys = extractAPIKeys(body)
	e.SSHKeys = extractSSHKeys(body)
	e.DBVersion = extractDBVersion(body)
	e.DBName = extractDBName(body)
	e.EnvVars = extractEnvVars(body)
	e.AWSCreds = extractAWSCreds(body)
	e.SourceCode = extractSourceCode(body)

	return e
}

// Total returns the total number of items extracted.
func (e *Extract) Total() int {
	return len(e.Emails) + len(e.Tokens) + len(e.Passwords) + len(e.IPs) +
		len(e.Filepaths) + len(e.APIKeys) + len(e.SSHKeys) + len(e.EnvVars) +
		len(e.AWSCreds) + len(e.SourceCode)
}

// ── Individual extractors ────────────────────────────────────────────────

var emailRE = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

func extractEmails(s string) []string { return unique(emailRE.FindAllString(s, -1)) }

var tokenRE = regexp.MustCompile(`(?i)(token|secret|key|password|passwd|pwd)[\s:=]+["']?([a-zA-Z0-9_\-\.]{20,})["']?`)

func extractTokens(s string) []string {
	var toks []string
	for _, m := range tokenRE.FindAllStringSubmatch(s, -1) {
		if len(m) >= 3 {
			toks = append(toks, m[2])
		}
	}
	return unique(toks)
}

var passwordRE = regexp.MustCompile(`(?i)(?:password|passwd|pwd)[\s:=]+["']([^"'\s]{6,})["']`)

func extractPasswords(s string) []string {
	var pws []string
	for _, m := range passwordRE.FindAllStringSubmatch(s, -1) {
		if len(m) >= 2 { pws = append(pws, m[1]) }
	}
	return unique(pws)
}

var ipRE = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

func extractIPs(s string) []string { return unique(ipRE.FindAllString(s, -1)) }

var pathRE = regexp.MustCompile(`/(?:[a-zA-Z0-9_\-\.]+/){1,10}[a-zA-Z0-9_\-\.]+`)

func extractFilepaths(s string) []string { return unique(pathRE.FindAllString(s, -1)) }

var apikeyRE = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api[_-]?secret)[\s:=]+["']?([a-zA-Z0-9_\-]{20,})["']?`)

func extractAPIKeys(s string) []string {
	var keys []string
	for _, m := range apikeyRE.FindAllStringSubmatch(s, -1) {
		if len(m) >= 2 { keys = append(keys, m[1]) }
	}
	return unique(keys)
}

var awsRE = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

func extractAWSCreds(s string) []string { return unique(awsRE.FindAllString(s, -1)) }

var dbVerRE = regexp.MustCompile(`(?i)(MySQL|PostgreSQL|MariaDB|Microsoft SQL Server|Oracle Database|MongoDB|Redis|SQLite)[\s\w]*([0-9]+[\.0-9]+)`)

func extractDBVersion(s string) string {
	m := dbVerRE.FindStringSubmatch(s)
	if len(m) >= 3 { return m[0] }
	if len(m) >= 2 { return m[1] }
	return ""
}

var dbNameRE = regexp.MustCompile(`(?i)(?:database|db_name|dbname|schema)[\s:=]+["']?([a-zA-Z][a-zA-Z0-9_]{1,30})["']?`)

func extractDBName(s string) string {
	m := dbNameRE.FindStringSubmatch(s)
	if len(m) >= 2 { return m[1] }
	return ""
}

var sshRE = regexp.MustCompile(`-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----`)

func extractSSHKeys(s string) []string {
	var keys []string
	for _, m := range sshRE.FindAllString(s, -1) {
		if m != "" { keys = append(keys, "SSH private key found") }
	}
	return keys
}

var envRE = regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]+)=(.+)$`)

func extractEnvVars(s string) []string {
	var vars []string
	for _, m := range envRE.FindAllStringSubmatch(s, -1) {
		if len(m) >= 3 {
			vars = append(vars, m[1]+"="+m[2])
		}
	}
	return unique(vars)
}

var codeRE = regexp.MustCompile(`(?s)(?:<\?(?:php|=)?|<\%.*\%>|<%@.*%>|def [a-z_]+\()(.+?)`)

func extractSourceCode(s string) []string {
	var code []string
	for _, m := range codeRE.FindAllStringSubmatch(s, -1) {
		if len(m) >= 2 && len(m[1]) > 10 {
			code = append(code, m[1][:min(100, len(m[1]))])
		}
	}
	return unique(code)
}

// ── JWT decoder ──────────────────────────────────────────────────────────

// DecodeJWT extracts the payload from a JWT token without verifying.
func DecodeJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ── Utilities ─────────────────────────────────────────────────────────────

func unique(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
