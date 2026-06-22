// Package vault extracts and validates credentials from response bodies,
// error messages, and configuration files discovered during scanning.
package vault

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// ── Types ────────────────────────────────────────────────────────────────

// Gem is one extracted credential with classification.
type Gem struct {
	Type     string `json:"type"`     // "password", "api_key", "token", "db_uri", "ssh_key", "cloud_key"
	Value    string `json:"value"`    // the actual credential value
	Context  string `json:"context"`  // surrounding text for verification
	Source   string `json:"source"`   // URL where it was found
	Severity string `json:"severity"` // CRITICAL, HIGH, MEDIUM
}

// Loot holds all credentials extracted from a scan.
type Loot struct {
	Gems   []Gem
	Counts map[string]int
	mu     sync.Mutex
}

// ── Extractor ─────────────────────────────────────────────────────────────

// Plunder scans a response body for credentials using regex and pattern
// matching. Returns all Gems found, classified by type.
func Plunder(body, sourceURL string) *Loot {
	l := &Loot{
		Counts: make(map[string]int),
	}

	// Password patterns
	passwordPatterns := []string{
		`(?i)(?:password|passwd|pwd|pass)[\s:=]+["']([^"'\s]{6,})["']`,
		`(?i)"password"\s*:\s*"([^"]+)"`,
	}
	for _, pat := range passwordPatterns {
		re := regexp.MustCompile(pat)
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				l.add(Gem{Type: "password", Value: m[1], Context: m[0], Source: sourceURL, Severity: "CRITICAL"})
			}
		}
	}

	// API key patterns
	apiKeyPatterns := []string{
		`["']?api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`,
		`["']?secret[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`,
	}
	for _, pat := range apiKeyPatterns {
		re := regexp.MustCompile(pat)
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				l.add(Gem{Type: "api_key", Value: m[1], Context: m[0], Source: sourceURL, Severity: "HIGH"})
			}
		}
	}

	// Database URI patterns
	dbURIPatterns := []string{
		`(?:mysql|postgres|mongodb|redis|sqlite)://[^\s"']+`,
		`DATABASE_URL\s*=\s*["']([^"']+)["']`,
		`(?i)(?:connectionString|connection_string)[\s:=]+["']([^"']+)["']`,
	}
	for _, pat := range dbURIPatterns {
		re := regexp.MustCompile(pat)
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			val := m[0]
			if len(m) >= 2 { val = m[1] }
			l.add(Gem{Type: "db_uri", Value: val, Context: m[0], Source: sourceURL, Severity: "CRITICAL"})
		}
	}

	// JWT / Bearer tokens
	tokenPatterns := []string{
		`eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}`,
		`Bearer\s+([a-zA-Z0-9_\-\.]{20,})`,
		`Authorization\s*:\s*["']?Bearer\s+([a-zA-Z0-9_\-\.]{20,})`,
	}
	for _, pat := range tokenPatterns {
		re := regexp.MustCompile(pat)
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			val := m[0]
			if len(m) >= 2 { val = m[1] }
			l.add(Gem{Type: "token", Value: val, Context: m[0], Source: sourceURL, Severity: "HIGH"})
		}
	}

	// AWS credentials
	awsPatterns := []string{
		`AKIA[0-9A-Z]{16}`,
		`(?i)aws_access_key_id\s*=\s*["']?([A-Z0-9]{20})["']?`,
		`(?i)aws_secret_access_key\s*=\s*["']?([a-zA-Z0-9/+=]{40})["']?`,
	}
	for _, pat := range awsPatterns {
		re := regexp.MustCompile(pat)
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			val := m[0]
			if len(m) >= 2 { val = m[1] }
			l.add(Gem{Type: "cloud_key", Value: val, Context: m[0], Source: sourceURL, Severity: "CRITICAL"})
		}
	}

	// Private keys
	if strings.Contains(body, "-----BEGIN") && strings.Contains(body, "PRIVATE KEY-----") {
		l.add(Gem{Type: "ssh_key", Value: "private key found", Context: "contains private key block", Source: sourceURL, Severity: "CRITICAL"})
	}

	return l
}

// ── Operations ────────────────────────────────────────────────────────────

func (l *Loot) add(g Gem) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Gems = append(l.Gems, g)
	l.Counts[g.Type]++
}

// Total returns the number of credentials found.
func (l *Loot) Total() int { return len(l.Gems) }

// Summary returns a one-line breakdown.
func (l *Loot) Summary() string {
	parts := make([]string, 0, len(l.Counts))
	for t, n := range l.Counts {
		parts = append(parts, fmt.Sprintf("%d %s(s)", n, t))
	}
	if len(parts) == 0 { return "no credentials found" }
	return strings.Join(parts, ", ")
}

// Markdown returns a credential disclosure report in Markdown.
func (l *Loot) Markdown() string {
	if len(l.Gems) == 0 { return "" }
	var sb strings.Builder
	sb.WriteString("## Credentials Extracted\n\n")
	sb.WriteString("| Type | Value (partial) | Source | Severity |\n")
	sb.WriteString("|---|---|---|---|\n")
	for _, g := range l.Gems {
		masked := mask(g.Value)
		sb.WriteString(fmt.Sprintf("| %s | `%s` | %s | %s |\n", g.Type, masked, g.Source, g.Severity))
	}
	return sb.String()
}

// ── Utilities ─────────────────────────────────────────────────────────────

func mask(s string) string {
	if len(s) <= 8 { return strings.Repeat("*", len(s)) }
	return s[:4] + strings.Repeat("*", min(8, len(s)-8)) + s[len(s)-4:]
}

// ── Compile guard ─────────────────────────────────────────────────────────
var _ = json.Marshal
