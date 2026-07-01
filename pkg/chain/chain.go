// Package chain correlates individual findings to discover compound
// attacks where the combination escalates severity far beyond each
// standalone vulnerability.
//
// Example chains detected:
//
//	Open Redirect + OAuth                    = Account Takeover (LOW+LOW -> CRITICAL)
//	IDOR + File Upload                       = Arbitrary File Write (HIGH+MEDIUM -> CRITICAL)
//	LFI + Log Poisoning                      = Remote Code Execution (HIGH+LOW -> CRITICAL)
//	SSRF + Internal Admin Panel              = Internal Network Pivot (HIGH+LOW -> CRITICAL)
//	Cookie Audit (Secure:false) + XSS        = Session Hijacking (LOW+MEDIUM -> HIGH)
//	JWT (none alg) + IDOR                    = Mass Data Exposure (HIGH+HIGH -> CRITICAL)
package chain

import (
	"fmt"
	"strings"
)

// ── Types ────────────────────────────────────────────────────────────────

// Link describes one finding in a larger attack chain.
type Link struct {
	ID   string `json:"id"`   // original finding type
	URL  string `json:"url"`  // vulnerable endpoint
	Role string `json:"role"` // "entry", "pivot", "escalation", "impact"
}

// Combo is a correlated attack chain with a significantly higher severity.
type Combo struct {
	Name     string   `json:"name"`      // human-readable chain name
	Steps    []Link   `json:"steps"`     // ordered attack steps
	Severity string   `json:"severity"`   // escalated severity
	Impact   string   `json:"impact"`    // what the attacker achieves
	CVSS     string   `json:"cvss"`      // CVSS for the combined attack
	Evidence string   `json:"evidence"`  // how we know the chain is viable
}

// ── Finding type → internal tag ──────────────────────────────────────────

func tag(findingType string) string {
	up := strings.ToUpper(findingType)
	switch {
	case strings.Contains(up, "OPEN REDIRECT"):
		return "open_redirect"
	case strings.Contains(up, "OAUTH"):
		return "oauth"
	case strings.Contains(up, "IDOR"):
		return "idor"
	case strings.Contains(up, "FILE UPLOAD"):
		return "file_upload"
	case strings.Contains(up, "LFI"):
		return "lfi"
	case strings.Contains(up, "RFI"):
		return "rfi"
	case strings.Contains(up, "SSRF"):
		return "ssrf"
	case strings.Contains(up, "XSS"):
		return "xss"
	case strings.Contains(up, "SQL"):
		return "sqli"
	case strings.Contains(up, "CMDI") || strings.Contains(up, "COMMAND INJECTION"):
		return "cmdi"
	case strings.Contains(up, "JWT") && strings.Contains(up, "NONE"):
		return "jwt_none"
	case strings.Contains(up, "JWT"):
		return "jwt"
	case strings.Contains(up, "COOKIE") && strings.Contains(up, "SECURE"):
		return "cookie_insecure"
	case strings.Contains(up, "COOKIE") && strings.Contains(up, "HTTPONLY"):
		return "cookie_nohttponly"
	case strings.Contains(up, "CSRF"):
		return "csrf"
	case strings.Contains(up, "PROTOTYPE POLLUTION"):
		return "proto_pollution"
	case strings.Contains(up, "CORS"):
		return "cors"
	case strings.Contains(up, "SENSITIVE FILE"):
		return "exposed_file"
	case strings.Contains(up, "SUBDOMAIN TAKEOVER"):
		return "takeover"
	case strings.Contains(up, "ADMIN PANEL") || strings.Contains(up, "PANEL"):
		return "admin_panel"
	case strings.Contains(up, "LOG POISON"):
		return "log_poison"
	case strings.Contains(up, "GRAPHQL"):
		return "graphql"
	case strings.Contains(up, "SMUGGLING"):
		return "smuggling"
	case strings.Contains(up, "CACHE POISON"):
		return "cache_poison"
	case strings.Contains(up, "DESERIAL"):
		return "deserialize"
	default:
		return "other"
	}
}

// ── Correlation engine ───────────────────────────────────────────────────

// Stitch analyzes a set of findings and returns any attack chains where
// the combined impact exceeds the individual severities.
func Stitch(findings []Finding) []Combo {
	if len(findings) < 2 {
		return nil
	}

	// Build a tag set for quick lookup
	have := make(map[string][]Finding)
	for _, f := range findings {
		t := tag(f.Type)
		have[t] = append(have[t], f)
	}

	var combos []Combo

	// Pattern 1: Open Redirect + OAuth → Account Takeover
	if len(have["open_redirect"]) > 0 && len(have["oauth"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Account Takeover via OAuth Redirect Hijack",
			Steps: []Link{
				{ID: have["open_redirect"][0].Type, URL: have["open_redirect"][0].URL, Role: "entry"},
				{ID: have["oauth"][0].Type, URL: have["oauth"][0].URL, Role: "escalation"},
			},
			Severity: "CRITICAL",
			Impact:   "Attacker can hijack OAuth flow via open redirect, stealing authorization codes and accessing victim accounts.",
			CVSS:     "9.6 CRITICAL",
			Evidence: fmt.Sprintf("Open redirect at %s can be chained with OAuth endpoint at %s", have["open_redirect"][0].URL, have["oauth"][0].URL),
		})
	}

	// Pattern 2: LFI + Log Poison → RCE
	if len(have["lfi"]) > 0 && len(have["log_poison"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Remote Code Execution via LFI + Log File Poisoning",
			Steps: []Link{
				{ID: have["lfi"][0].Type, URL: have["lfi"][0].URL, Role: "entry"},
				{ID: have["log_poison"][0].Type, URL: have["log_poison"][0].URL, Role: "escalation"},
			},
			Severity: "CRITICAL",
			Impact:   "Attacker injects PHP code into server logs via User-Agent header, then includes the log file via LFI to execute arbitrary commands.",
			CVSS:     "10.0 CRITICAL",
			Evidence: fmt.Sprintf("LFI at %s can include %s after log poisoning", have["lfi"][0].URL, have["log_poison"][0].URL),
		})
	}

	// Pattern 3: JWT none alg + IDOR → Mass Data Exposure
	if len(have["jwt_none"]) > 0 && len(have["idor"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Mass Data Exposure via JWT Bypass + IDOR",
			Steps: []Link{
				{ID: have["jwt_none"][0].Type, URL: have["jwt_none"][0].URL, Role: "entry"},
				{ID: have["idor"][0].Type, URL: have["idor"][0].URL, Role: "escalation"},
			},
			Severity: "CRITICAL",
			Impact:   "Attacker forges JWT tokens with alg:none to impersonate any user, then enumerates all records via IDOR.",
			CVSS:     "9.8 CRITICAL",
			Evidence: fmt.Sprintf("JWT bypass at %s + IDOR at %s = impersonated data access to all records", have["jwt_none"][0].URL, have["idor"][0].URL),
		})
	}

	// Pattern 4: SSRF + Internal Admin Panel → Internal Network Pivot
	if len(have["ssrf"]) > 0 && len(have["admin_panel"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Internal Network Pivot via SSRF to Admin Panel",
			Steps: []Link{
				{ID: have["ssrf"][0].Type, URL: have["ssrf"][0].URL, Role: "entry"},
				{ID: have["admin_panel"][0].Type, URL: have["admin_panel"][0].URL, Role: "pivot"},
			},
			Severity: "CRITICAL",
			Impact:   "SSRF allows reaching internal services; admin panel found on the network can be accessed and compromised.",
			CVSS:     "9.1 CRITICAL",
			Evidence: fmt.Sprintf("SSRF at %s can reach internal admin panel at %s", have["ssrf"][0].URL, have["admin_panel"][0].URL),
		})
	}

	// Pattern 5: Cookie Secure:false + XSS → Session Hijacking
	if len(have["cookie_insecure"]) > 0 && len(have["xss"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Session Hijacking via XSS + Insecure Cookies",
			Steps: []Link{
				{ID: have["xss"][0].Type, URL: have["xss"][0].URL, Role: "entry"},
				{ID: have["cookie_insecure"][0].Type, URL: have["cookie_insecure"][0].URL, Role: "escalation"},
			},
			Severity: "HIGH",
			Impact:   "XSS allows cookie theft; missing Secure flag means cookies can be exfiltrated over unencrypted channels.",
			CVSS:     "8.8 HIGH",
			Evidence: fmt.Sprintf("XSS at %s + cookies without Secure flag at %s = session theft possible", have["xss"][0].URL, have["cookie_insecure"][0].URL),
		})
	}

	// Pattern 6: IDOR + File Upload → Arbitrary File Write
	if len(have["idor"]) > 0 && len(have["file_upload"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Arbitrary File Write via IDOR + File Upload",
			Steps: []Link{
				{ID: have["idor"][0].Type, URL: have["idor"][0].URL, Role: "entry"},
				{ID: have["file_upload"][0].Type, URL: have["file_upload"][0].URL, Role: "escalation"},
			},
			Severity: "CRITICAL",
			Impact:   "IDOR allows targeting another user's profile; file upload writes malicious files in their context.",
			CVSS:     "9.8 CRITICAL",
			Evidence: fmt.Sprintf("IDOR at %s + file upload at %s = write files as any user", have["idor"][0].URL, have["file_upload"][0].URL),
		})
	}

	// Pattern 7: CSRF + any state-changing endpoint
	if len(have["csrf"]) > 0 && (len(have["sqli"]) > 0 || len(have["idor"]) > 0 || len(have["file_upload"]) > 0) {
		sq := have["sqli"]
		id := have["idor"]
		fu := have["file_upload"]
		var victim string
		if len(sq) > 0 { victim = sq[0].URL }
		if len(id) > 0 { victim = id[0].URL }
		if len(fu) > 0 { victim = fu[0].URL }

		combos = append(combos, Combo{
			Name:  "Forced State Change via CSRF",
			Steps: []Link{
				{ID: have["csrf"][0].Type, URL: have["csrf"][0].URL, Role: "entry"},
				{ID: "state-changing endpoint", URL: victim, Role: "impact"},
			},
			Severity: "HIGH",
			Impact:   "Lack of CSRF protection allows attacker to force authenticated victims to perform actions on their behalf.",
			CVSS:     "8.1 HIGH",
			Evidence: fmt.Sprintf("CSRF vulnerability at %s allows forging requests to %s", have["csrf"][0].URL, victim),
		})
	}

	// Pattern 8: Proto Pollution + XSS → Client-Side RCE
	if len(have["proto_pollution"]) > 0 && len(have["xss"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Client-Side RCE via Prototype Pollution + XSS",
			Steps: []Link{
				{ID: have["proto_pollution"][0].Type, URL: have["proto_pollution"][0].URL, Role: "entry"},
				{ID: have["xss"][0].Type, URL: have["xss"][0].URL, Role: "escalation"},
			},
			Severity: "CRITICAL",
			Impact:   "Prototype pollution corrupts JavaScript runtime; XSS delivers the payload to victim browsers.",
			CVSS:     "9.1 CRITICAL",
			Evidence: fmt.Sprintf("Prototype pollution at %s + XSS at %s = client-side code execution", have["proto_pollution"][0].URL, have["xss"][0].URL),
		})
	}

	// Pattern 9: Cache Poison + XSS → Persistent XSS
	if len(have["cache_poison"]) > 0 && len(have["xss"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Persistent (Stored) XSS via Cache Poisoning",
			Steps: []Link{
				{ID: have["cache_poison"][0].Type, URL: have["cache_poison"][0].URL, Role: "entry"},
				{ID: have["xss"][0].Type, URL: have["xss"][0].URL, Role: "impact"},
			},
			Severity: "CRITICAL",
			Impact:   "Cache poisoning makes XSS persistent — every visitor to the poisoned page executes the attacker's script.",
			CVSS:     "9.6 CRITICAL",
			Evidence: fmt.Sprintf("Cache poison at %s can embed XSS payload from %s into cached response", have["cache_poison"][0].URL, have["xss"][0].URL),
		})
	}

	// Pattern 10: Deserialization + File Upload → RCE
	if len(have["deserialize"]) > 0 && len(have["file_upload"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Remote Code Execution via Deserialization + File Upload",
			Steps: []Link{
				{ID: have["file_upload"][0].Type, URL: have["file_upload"][0].URL, Role: "entry"},
				{ID: have["deserialize"][0].Type, URL: have["deserialize"][0].URL, Role: "escalation"},
			},
			Severity: "CRITICAL",
			Impact:   "Upload a serialized malicious object, then trigger deserialization to execute arbitrary code.",
			CVSS:     "10.0 CRITICAL",
			Evidence: fmt.Sprintf("File upload at %s + deserialization at %s = RCE via malicious serialized object", have["file_upload"][0].URL, have["deserialize"][0].URL),
		})
	}

	// Pattern 11: Subdomain Takeover + CSP/Headers → Full Site Control
	if len(have["takeover"]) > 0 {
		combos = append(combos, Combo{
			Name:  "Full Site Control via Subdomain Takeover",
			Steps: []Link{
				{ID: have["takeover"][0].Type, URL: have["takeover"][0].URL, Role: "entry"},
			},
			Severity: "CRITICAL",
			Impact:   "Attacker claims the dangling subdomain and hosts malicious content under the target's domain name.",
			CVSS:     "9.8 CRITICAL",
			Evidence: fmt.Sprintf("Dangling subdomain at %s can be claimed and used for phishing, cookie theft, or content injection", have["takeover"][0].URL),
		})
	}

	return combos
}

// ── Input type ───────────────────────────────────────────────────────────

// Finding is a simplified scan result for correlation input.
type Finding struct {
	Type     string
	Severity string
	URL      string
	Evidence string
}

// ── Utility ──────────────────────────────────────────────────────────────

// Summarize returns a one-line summary of the combo chain.
func (c *Combo) Summarize() string {
	var steps []string
	for _, s := range c.Steps {
		steps = append(steps, fmt.Sprintf("[%s] %s", s.Role, s.ID))
	}
	return fmt.Sprintf("%s: %s -> %s", c.Name, strings.Join(steps, " -> "), c.Impact)
}
