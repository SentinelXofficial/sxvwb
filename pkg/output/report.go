package output

import (
	"github.com/SentinelXofficial/sxvwb/pkg/core"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

// cvssTable maps finding-type substrings to full CVSSv3.1 score + vector.
// Ordered slice — more-specific entries before general catch-alls.
var cvssTable = []struct{ key, val string }{
	// ── SQL Injection ───────────────────────────────────────────────────
	{"SQL Injection Time-Based", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"SQL Injection Boolean", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"SQL Injection via Form", "8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)"},
	{"SQL Injection via HTTP Header", "7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"SQL Injection via Cookie", "8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)"},
	{"SQL Injection via JSON", "8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)"},
	{"WebSocket SQL Injection", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"SQL Injection", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	// ── XSS ─────────────────────────────────────────────────────────────
	{"XSS (Reflected) via Form", "5.4 MEDIUM (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)"},
	{"XSS via HTTP Header", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"XSS via JSON", "5.4 MEDIUM (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)"},
	{"WebSocket XSS", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"XSS (Reflected)", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	// ── Command Injection ────────────────────────────────────────────────
	{"Command Injection via Form (Blind", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	{"Command Injection via Form", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	{"Command Injection (Blind", "10.0 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	{"Command Injection", "10.0 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	// ── SSRF ─────────────────────────────────────────────────────────────
	{"SSRF (Server-Side Request Forgery)", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"SSRF via Form (Server-Side Request Forgery)", "8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)"},
	{"SSRF (Error Leakage)", "6.5 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"SSRF via Form (Error Leakage)", "6.5 MEDIUM (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)"},
	{"SSRF (Timing/Port-Scan)", "5.8 MEDIUM (AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N)"},
	{"SSRF", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	// ── XXE ──────────────────────────────────────────────────────────────
	{"XXE (XML External Entity Injection)", "9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"},
	{"XXE (Potential — Anomalous Response)", "5.3 MEDIUM (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"XXE", "9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"},
	// ── NoSQL Injection ───────────────────────────────────────────────────
	{"NoSQL Injection (JSON Auth Bypass)", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"NoSQL Injection (Error-Based)", "7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"NoSQL Injection (Boolean-Based)", "8.1 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"NoSQL Injection via Form (Error-Based)", "7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"NoSQL Injection via Form (Boolean-Based)", "8.1 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"NoSQL Injection", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	// ── Directory Brute Force ─────────────────────────────────────────────
	{"Directory / File Found", "5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"},
	// ── Sprint 4 ─────────────────────────────────────────────────────────
	{"File Upload Vulnerability", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	{"JWT Algorithm None Bypass", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"JWT Algorithm Confusion", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"JWT Empty Signature Accepted", "9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"},
	{"JWT Weak Secret", "8.8 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"IDOR (Insecure Direct Object Reference)", "8.1 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)"},
	{"GraphQL Introspection Enabled", "5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"},
	{"GraphQL Field Suggestions Enabled", "3.7 LOW (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)"},
	{"GraphQL Batching Attack Possible", "6.5 MEDIUM (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L)"},
	{"GraphQL Query Depth Limit Not Enforced", "5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)"},
	{"GraphQL Alias-Based Resource Amplification", "5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)"},
	// ── Other ────────────────────────────────────────────────────────────
	{"SSTI", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"Path Traversal", "7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"Open Redirect", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"CORS Misconfiguration (Origin Reflection)", "8.1 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"CORS Misconfiguration (Wildcard)", "5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"},
	{"Security Header Issue", "4.3 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)"},
	{"Sensitive File/Endpoint Exposed", "7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"},
	{"Dangerous HTTP Method", "5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)"},
	{"CRLF Injection", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"Host Header Injection", "5.4 MEDIUM (AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N)"},
	// ── Sprint 5 — CSRF ───────────────────────────────────────────────────
	{"CSRF — Missing Anti-CSRF Token", "8.8 HIGH (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)"},
	{"CSRF — Token Not Enforced", "8.8 HIGH (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)"},
	// ── Sprint 5 — Cookie Security ────────────────────────────────────────
	{"Cookie Security — Missing Secure Flag", "4.3 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)"},
	{"Cookie Security — Missing HttpOnly Flag", "5.4 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)"},
	{"Cookie Security — SameSite Not Set", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"Cookie Security — SameSite=None Without Secure", "7.4 HIGH (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)"},
	{"Cookie Security — Broad Domain Scope", "3.7 LOW (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)"},
	{"Cookie Security — Long Expiry", "3.1 LOW (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)"},
	// ── Sprint 5 — Subdomain Enum ─────────────────────────────────────────
	{"Subdomain Discovered", "0 INFO"},
	// ── Sprint 5 — Prototype Pollution ────────────────────────────────────
	{"Prototype Pollution — Server-Side Reflection", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"Prototype Pollution — Potential (Response Anomaly)", "7.3 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"},
	// ── Sprint 5 — Deserialization ────────────────────────────────────────
	{"Insecure Deserialization", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	// ── Sprint 5 — Cache Poisoning ────────────────────────────────────────
	{"Web Cache Poisoning", "8.1 HIGH (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	{"Web Cache Poisoning (IP Header Reflection)", "6.5 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"Web Cache Poisoning (Host Header)", "8.1 HIGH (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	// ── Sprint 5 — LFI/RFI ────────────────────────────────────────────────
	{"LFI (Local File Inclusion)", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	{"LFI — Log File Poisoning", "10.0 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	{"RFI (Remote File Inclusion)", "10.0 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"},
	// ── Sprint 5 — Request Smuggling ──────────────────────────────────────
	{"HTTP Request Smuggling", "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	// ── Sprint 5 — Rate Limiting ──────────────────────────────────────────
	{"Rate Limiting Assessment", "0 INFO"},
	// ── Sprint 5 — Subdomain Takeover ─────────────────────────────────────
	{"Subdomain Takeover", "8.8 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
	// ── Sprint 5 — CORS Extended ──────────────────────────────────────────
	{"CORS — Preflight Accepted (Extended)", "6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"},
	{"CORS — Private Network Access Allowed", "8.1 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)"},
}

var remediationMap = map[string]string{
	"SQL Injection":      "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Consider an ORM. Apply principle of least privilege to DB accounts.",
	"XSS":               "HTML-encode all user-supplied output. Implement Content-Security-Policy header. Use templating engines that auto-escape. Validate and sanitize input.",
	"SSTI":              "Never pass user input to template engines. Use sandboxed environments. Prefer logic-less templates like Mustache.",
	"Path Traversal":    "Canonicalize paths with filepath.Abs / realpath. Validate against an allowed base directory. Use chroot / containerization.",
	"Open Redirect":     "Validate redirect targets against an allowlist of trusted domains. Avoid accepting full URLs in redirect parameters.",
	"CORS":              "Specify exact allowed origins. Never reflect arbitrary Origin headers. Avoid ACAC: true unless strictly necessary.",
	"Security Header":   "Add security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. Remove server version banners.",
	"Sensitive File":    "Remove dev/debug/backup files from production. Block .git access at server level. Use secrets managers instead of .env files.",
	"HTTP Method":       "Disable unused HTTP methods in server config. Apply strict method restrictions in application routes.",
	"CRLF":             "Sanitize \\r and \\n characters from user input before use in headers. Use framework header-setting APIs.",
	"Host Header":      "Validate the Host header against an allowlist. Use absolute URLs in redirects and canonical links.",
	"WebSocket":        "Apply same input validation to WebSocket messages as HTTP. Authenticate WebSocket connections. Enforce Origin checks.",
	// Sprint 2
	"Command Injection": "Never pass user input to shell commands. Use exec.Command with argument lists (not shell=true). Whitelist allowed inputs. Sandbox with containers/seccomp.",
	"SSRF":             "Validate and allowlist outbound URLs. Block private IP ranges (127.x, 10.x, 169.254.x). Disable unnecessary URL-fetching features. Use IMDSv2 on cloud instances.",
	"XXE":              "Disable external entity processing in XML parsers (FEATURE_SECURE_PROCESSING). Avoid accepting XML from untrusted sources. Use JSON where possible.",
	"NoSQL Injection":  "Use parameterized queries for NoSQL. Validate and sanitize operator characters ($gt, $ne, etc.). Apply schema validation and type enforcement.",
	// Sprint 3
	"Directory":        "Restrict directory listings. Remove backup/dev/debug files from production. Use authentication for admin paths. Implement proper access controls.",
	// Sprint 4
	"File Upload":      "Validate file type by content (magic bytes), not extension or MIME header. Store uploads outside web root. Serve via separate domain. Strip executable permissions.",
	"JWT":              "Always verify JWT signatures server-side. Reject alg=none. Use asymmetric keys for RS256; never use the public key as an HMAC secret. Enforce strong secret entropy.",
	"IDOR":             "Enforce ownership checks on every object access. Never trust client-supplied IDs alone. Use UUIDs instead of sequential integers where possible.",
	"GraphQL":          "Disable introspection in production. Remove field suggestions. Implement query depth and complexity limits. Add per-IP rate limiting on the GraphQL endpoint.",
	// Sprint 5
	"CSRF":             "Add anti-CSRF tokens to all state-changing forms. Validate tokens server-side on every request. Combine with SameSite=Strict/Lax cookies.",
	"Cookie Security":  "Set Secure, HttpOnly, and SameSite=Lax/Strict on all cookies. Use short expiry for session cookies. Restrict Domain and Path to the minimum scope needed.",
	"Subdomain":        "Remove unused DNS records. Implement proper subdomain inventory management. Monitor certificate transparency logs for unauthorized subdomains.",
	"Prototype Pollution": "Use Object.create(null) for objects that hold user-supplied keys. Sanitize __proto__ and constructor keys. Use Map instead of plain objects where possible.",
	"Deserialization":  "Never deserialize untrusted data without integrity checks. Use HMAC-signed serialization. Prefer safe formats like JSON over native serialization. Implement type allowlists.",
	"Cache Poisoning":  "Configure cache keys to include relevant request headers. Disable caching of responses affected by unkeyed headers. Use Vary header appropriately.",
	"LFI":              "Whitelist allowed file paths. Use basename() instead of user-supplied paths. Disable allow_url_include in PHP. Never pass user input to include/require.",
	"Request Smuggling": "Use HTTP/2 end-to-end to avoid request smuggling. Disable backend connection reuse. Normalize ambiguous requests at the proxy. Keep web server software updated.",
	"Rate Limiting":    "Implement per-IP and per-endpoint rate limiting. Use 429 status codes with Retry-After headers. Apply stricter limits to authentication endpoints.",
	"Subdomain Takeover": "Remove DNS records pointing to decommissioned services. Verify CNAME targets are still claimed. Implement automated takeover detection.",
}

func CVSSFor(t string) string {
	up := strings.ToUpper(t)
	for _, entry := range cvssTable {
		if strings.Contains(up, strings.ToUpper(entry.key)) {
			return entry.val
		}
	}
	return "-"
}

func RemediationFor(t string) string {
	up := strings.ToUpper(t)
	pairs := []struct{ key, mapKey string }{
		{"COMMAND INJECTION", "Command Injection"},
		{"SSRF", "SSRF"},
		{"XXE", "XXE"},
		{"NOSQL", "NoSQL Injection"},
		{"DIRECTORY / FILE", "Directory"},
		// Sprint 4
		{"FILE UPLOAD", "File Upload"},
		{"JWT", "JWT"},
		{"IDOR", "IDOR"},
		{"GRAPHQL", "GraphQL"},
		{"SQL", "SQL Injection"},
		{"XSS", "XSS"},
		{"SSTI", "SSTI"},
		{"PATH TRAVERSAL", "Path Traversal"},
		{"OPEN REDIRECT", "Open Redirect"},
		{"CORS", "CORS"},
		{"SECURITY HEADER", "Security Header"},
		{"SENSITIVE", "Sensitive File"},
		{"HTTP METHOD", "HTTP Method"},
		{"CRLF", "CRLF"},
		{"HOST HEADER", "Host Header"},
		{"WEBSOCKET", "WebSocket"},
		// Sprint 5
		{"CSRF", "CSRF"},
		{"COOKIE SECURITY", "Cookie Security"},
		{"SUBDOMAIN", "Subdomain"},
		{"PROTOTYPE POLLUTION", "Prototype Pollution"},
		{"INSECURE DESERIALIZATION", "Deserialization"},
		{"WEB CACHE POISONING", "Cache Poisoning"},
		{"LFI", "LFI"},
		{"RFI", "LFI"},
		{"HTTP REQUEST SMUGGLING", "Request Smuggling"},
		{"RATE LIMITING ASSESSMENT", "Rate Limiting"},
		{"SUBDOMAIN TAKEOVER", "Subdomain Takeover"},
	}
	for _, p := range pairs {
		if strings.Contains(up, p.key) {
			return remediationMap[p.mapKey]
		}
	}
	return "Review and apply OWASP guidelines for this vulnerability class."
}

// Dedup removes results with identical type+url+parameter combinations,
// keeping the entry with the shortest (cleanest) payload for each group.
func Dedup(results []core.ScanResult) []core.ScanResult {
	order := []string{}
	best := map[string]core.ScanResult{}
	for _, r := range results {
		key := r.Type + "|" + r.URL + "|" + r.Parameter
		cur, exists := best[key]
		if !exists {
			order = append(order, key)
			best[key] = r
			continue
		}
		if len(r.Payload) < len(cur.Payload) {
			best[key] = r
		}
	}
	out := make([]core.ScanResult, 0, len(order))
	for _, key := range order {
		out = append(out, best[key])
	}
	return out
}

func Enrich(results []core.ScanResult) []core.ReportEntry {
	var out []core.ReportEntry
	for _, r := range results {
		entry := core.ReportEntry{
			CVSS:        CVSSFor(r.Type),
			Remediation: RemediationFor(r.Type),
		}
		entry.ScanResult = r
		out = append(out, entry)
	}
	return out
}

func ComputeStats(results []core.ScanResult, totalURLs, totalForms int) core.ScanStats {
	s := core.ScanStats{TotalURLs: totalURLs, TotalForms: totalForms}
	for _, r := range results {
		switch r.Severity {
		case "HIGH":
			s.HighCount++
		case "MEDIUM":
			s.MediumCount++
		case "LOW":
			s.LowCount++
		case "INFO":
			s.InfoCount++
		}
		up := strings.ToUpper(r.Type)
		switch {
		case strings.Contains(up, "SQL"):
			s.SQLiCount++
		case strings.Contains(up, "XSS"):
			s.XSSCount++
		case strings.Contains(up, "WEBSOCKET"):
			s.WSCount++
		default:
			s.OtherCount++
		}
	}
	return s
}

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>sxsc Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;line-height:1.6}
.wrap{max-width:1150px;margin:0 auto}
.hdr{background:linear-gradient(135deg,#161b22,#1f2937);padding:26px 30px;border-radius:12px;margin-bottom:20px;border:1px solid #30363d}
.hdr h1{color:#f0883e;font-size:22px;margin-bottom:6px}
.meta{color:#8b949e;font-size:13px}.meta b{color:#79c0ff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;text-align:center}
.num{font-size:30px;font-weight:700}.lbl{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.r{color:#f85149}.o{color:#e3b341}.g{color:#3fb950}.b{color:#79c0ff}
.stitle{font-size:16px;font-weight:600;color:#f0f6fc;border-bottom:1px solid #30363d;padding-bottom:8px;margin-bottom:14px}
.vc{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:12px;overflow:hidden}
.vh{display:flex;align-items:center;gap:10px;padding:11px 16px;border-bottom:1px solid #21262d}
.badge{padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700}
.HIGH{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.4)}
.MEDIUM{background:rgba(227,179,65,.15);color:#e3b341;border:1px solid rgba(227,179,65,.4)}
.LOW{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.4)}
.INFO{background:rgba(121,192,255,.15);color:#79c0ff;border:1px solid rgba(121,192,255,.4)}
.vt{font-weight:600;color:#f0f6fc;flex:1}.cvss{font-size:11px;color:#8b949e}
.vb{padding:12px 16px}
.row{display:flex;gap:10px;padding:4px 0;border-bottom:1px solid #21262d;font-size:13px}
.row:last-child{border:none}.key{color:#8b949e;min-width:100px;flex-shrink:0}
.val{color:#c9d1d9;word-break:break-all}
code{background:#0d1117;color:#79c0ff;padding:2px 5px;border-radius:4px;font-family:Consolas,monospace;font-size:12px}
.remedy{background:#0d1117;border-left:3px solid #f0883e;padding:8px 12px;margin-top:8px;font-size:12px;color:#8b949e;border-radius:0 4px 4px 0}
.empty{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:48px;text-align:center;color:#3fb950;font-size:17px}
.foot{text-align:center;color:#484f58;font-size:11px;margin-top:24px;padding-top:14px;border-top:1px solid #21262d}
</style>
</head><body>
<div class="wrap">
<div class="hdr">
  <h1>sxsc — SentinelX Scanner Report</h1>
  <div class="meta">Target: <b>{{.Target}}</b></div>
  <div class="meta">Date: <b>{{.StartTime}}</b> | Duration: <b>{{.Duration}}</b></div>
</div>
<div class="grid">
  <div class="card"><div class="num b">{{.Stats.TotalURLs}}</div><div class="lbl">URLs Scanned</div></div>
  <div class="card"><div class="num b">{{.Stats.TotalForms}}</div><div class="lbl">Forms Tested</div></div>
  <div class="card"><div class="num r">{{.Stats.HighCount}}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num o">{{.Stats.MediumCount}}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num r">{{.Stats.SQLiCount}}</div><div class="lbl">SQLi</div></div>
  <div class="card"><div class="num o">{{.Stats.XSSCount}}</div><div class="lbl">XSS</div></div>
  <div class="card"><div class="num b">{{.Stats.OtherCount}}</div><div class="lbl">Other</div></div>
  <div class="card"><div class="num">{{len .Results}}</div><div class="lbl">Total</div></div>
</div>
<div class="stitle">Findings ({{len .Results}})</div>
{{if .Results}}{{range .Results}}
<div class="vc">
  <div class="vh">
    <span class="badge {{.Severity}}">{{.Severity}}</span>
    <span class="vt">{{.Type}}</span>
    <span class="cvss">CVSS {{.CVSS}}</span>
  </div>
  <div class="vb">
    <div class="row"><span class="key">Method</span><span class="val"><code>{{.Method}}</code></span></div>
    <div class="row"><span class="key">Parameter</span><span class="val"><code>{{.Parameter}}</code></span></div>
    <div class="row"><span class="key">Payload</span><span class="val"><code>{{.Payload}}</code></span></div>
    <div class="row"><span class="key">Evidence</span><span class="val">{{.Evidence}}</span></div>
    <div class="row"><span class="key">URL</span><span class="val"><code>{{.URL}}</code></span></div>
    <div class="row"><span class="key">Time</span><span class="val">{{.Timestamp | fmtTime}}</span></div>
    <div class="remedy"><b>Remediation:</b> {{.Remediation}}</div>
  </div>
</div>
{{end}}{{else}}<div class="empty">No vulnerabilities detected</div>{{end}}
<div class="foot">sxsc — Only test systems you own or have explicit written permission to test.</div>
</div></body></html>`

func SaveHTMLReport(results []core.ScanResult, target, filename string, elapsed time.Duration, totalURLs, totalForms int) error {
	fm := template.FuncMap{"fmtTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") }}
	tmpl, err := template.New("r").Funcs(fm).Parse(htmlTmpl)
	if err != nil {
		return err
	}
	report := core.ScanReport{
		Target:    target,
		StartTime: time.Now().Format("2006-01-02 15:04:05"),
		Duration:  elapsed.Round(time.Millisecond).String(),
		Results:   Enrich(results),
		Stats:     ComputeStats(results, totalURLs, totalForms),
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return err
	}
	return os.WriteFile(filename, buf.Bytes(), 0600)
}

func SaveJSONReport(results []core.ScanResult, target, filename string) error {
	type out struct {
		Target    string       `json:"target"`
		Timestamp time.Time    `json:"timestamp"`
		Count     int          `json:"count"`
		Results   []core.ScanResult `json:"results"`
	}
	data, err := json.MarshalIndent(out{target, time.Now(), len(results), results}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

// buildMarkdownReport renders the Markdown report body.
func buildMarkdownReport(results []core.ScanResult, target string, elapsed time.Duration, totalURLs, totalForms int) string {
	stats := ComputeStats(results, totalURLs, totalForms)
	entries := Enrich(results)

	var b strings.Builder
	fmt.Fprintf(&b, "# sxsc — SentinelX Scanner Report\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`  \n", target)
	fmt.Fprintf(&b, "**Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "**Duration:** %s  \n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "**Scanned:** %d URL(s), %d form(s)\n\n", totalURLs, totalForms)

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Total | High | Medium | Low | Info | SQLi | XSS | WebSocket | Other |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		len(results), stats.HighCount, stats.MediumCount, stats.LowCount, stats.InfoCount,
		stats.SQLiCount, stats.XSSCount, stats.WSCount, stats.OtherCount)

	fmt.Fprintf(&b, "## Findings (%d)\n\n", len(entries))
	if len(entries) == 0 {
		fmt.Fprintf(&b, "No vulnerabilities detected. This does not guarantee the target is fully secure.\n\n")
	}
	for i, e := range entries {
		fmt.Fprintf(&b, "### [%d] %s — `%s`\n\n", i+1, e.Type, e.Severity)
		fmt.Fprintf(&b, "- **CVSS:** %s\n", e.CVSS)
		fmt.Fprintf(&b, "- **Method:** %s\n", e.Method)
		fmt.Fprintf(&b, "- **Parameter:** `%s`\n", e.Parameter)
		fmt.Fprintf(&b, "- **Payload:** `%s`\n", e.Payload)
		fmt.Fprintf(&b, "- **Evidence:** %s\n", e.Evidence)
		fmt.Fprintf(&b, "- **URL:** `%s`\n", e.URL)
		fmt.Fprintf(&b, "- **Time:** %s\n", e.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(&b, "- **Remediation:** %s\n\n", e.Remediation)
	}

	fmt.Fprintf(&b, "---\n*sxsc — Only test systems you own or have explicit written permission to test.*\n")
	return b.String()
}

// SaveMarkdownReport writes a Markdown report to disk — handy for pasting
// into Notion, GitHub Issues, or a bug-bounty writeup (item [15] in roadmap).
func SaveMarkdownReport(results []core.ScanResult, target, filename string, elapsed time.Duration, totalURLs, totalForms int) error {
	body := buildMarkdownReport(results, target, elapsed, totalURLs, totalForms)
	return os.WriteFile(filename, []byte(body), 0600)
}

func SaveCSVReport(results []core.ScanResult, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"Type", "Severity", "CVSS", "Method", "Parameter", "Payload", "Evidence", "URL", "Timestamp"}) //nolint:errcheck
	for _, r := range results {
		w.Write([]string{ //nolint:errcheck
			r.Type, r.Severity, CVSSFor(r.Type), r.Method,
			r.Parameter, r.Payload, r.Evidence, r.URL,
			r.Timestamp.Format("2006-01-02 15:04:05"),
		})
	}
	w.Flush()
	return w.Error()
}

func PrintConsoleReport(results []core.ScanResult, target string, elapsed time.Duration, totalURLs, totalForms int) {
	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println("SCAN REPORT")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Target   : %s\n", target)
	fmt.Printf("Duration : %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Scanned  : %d URL(s), %d form(s)\n", totalURLs, totalForms)

	stats := ComputeStats(results, totalURLs, totalForms)
	fmt.Printf("Findings : %d total  HIGH:%d  MEDIUM:%d  LOW:%d  INFO:%d\n\n",
		len(results), stats.HighCount, stats.MediumCount, stats.LowCount, stats.InfoCount)

	if len(results) == 0 {
		fmt.Println("[OK] No vulnerabilities detected")
		fmt.Println("[!]  This does not guarantee the target is fully secure")
		return
	}

	for i, v := range results {
		sc := "\033[33m"
		if v.Severity == "HIGH" {
			sc = "\033[31m"
		} else if v.Severity == "LOW" {
			sc = "\033[32m"
		} else if v.Severity == "INFO" {
			sc = "\033[36m"
		}
		fmt.Printf("\033[1m[%d] %s\033[0m\n", i+1, v.Type)
		fmt.Printf("    %-12s : %s%s\033[0m  (CVSS %s)\n", "Severity", sc, v.Severity, CVSSFor(v.Type))
		fmt.Printf("    %-12s : %s\n", "Method", v.Method)
		fmt.Printf("    %-12s : %s\n", "Parameter", v.Parameter)
		fmt.Printf("    %-12s : %s\n", "Payload", v.Payload)
		fmt.Printf("    %-12s : %s\n", "Evidence", v.Evidence)
		fmt.Printf("    %-12s : %s\n\n", "URL", v.URL)
	}
	fmt.Println("[!] DISCLAIMER: Only test on systems you own or have explicit written permission to test.")
}
