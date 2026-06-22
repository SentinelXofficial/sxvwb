// Package merge probes the same endpoint with multiple Content-Type
// headers to find parsing inconsistencies. Many applications accept JSON
// but parse it differently from form data — creating vulnerabilities
// that single-Content-Type scanners miss entirely.
package merge

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Dialect is a Content-Type + encoding pair to test.
type Dialect struct {
	ContentType string
	Encoder     func(params map[string]string) string // encodes params for this Content-Type
}

// Shadow holds two responses to the same logical request with different
// Content-Types. A significant difference indicates parsing inconsistency.
type Shadow struct {
	URL       string
	Param     string
	DialectA  string
	StatusA   int
	BodyA     string
	DialectB  string
	StatusB   int
	BodyB     string
	Signature string // what's different
}

// ── Dialects ─────────────────────────────────────────────────────────────

// AllDialects returns common Content-Type dialects to try.
func AllDialects() []Dialect {
	return []Dialect{
		{
			ContentType: "application/x-www-form-urlencoded",
			Encoder: func(p map[string]string) string {
				vals := url.Values{}
				for k, v := range p { vals.Set(k, v) }
				return vals.Encode()
			},
		},
		{
			ContentType: "application/json",
			Encoder: func(p map[string]string) string {
				parts := make([]string, 0, len(p))
				for k, v := range p {
					parts = append(parts, fmt.Sprintf(`"%s":"%s"`, k, escapeJSON(v)))
				}
				return "{" + strings.Join(parts, ",") + "}"
			},
		},
		{
			ContentType: "application/xml",
			Encoder: func(p map[string]string) string {
				var b strings.Builder
				b.WriteString("<?xml version=\"1.0\"?><root>")
				for k, v := range p {
					b.WriteString(fmt.Sprintf("<%s>%s</%s>", k, escapeXML(v), k))
				}
				b.WriteString("</root>")
				return b.String()
			},
		},
		{
			ContentType: "multipart/form-data",
			Encoder: func(p map[string]string) string {
				boundary := "----sxscboundary"
				var b strings.Builder
				for k, v := range p {
					b.WriteString(fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", boundary, k, v))
				}
				b.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
				return b.String()
			},
		},
		{
			ContentType: "text/plain",
			Encoder: func(p map[string]string) string {
				vals := url.Values{}
				for k, v := range p { vals.Set(k, v) }
				return vals.Encode() // body is form-encoded but content-type says text/plain
			},
		},
	}
}

// ── Hammer ───────────────────────────────────────────────────────────────

// Hammer sends the same parameter set to an endpoint using every dialect.
// Returns any Shadow pairs where the responses differ meaningfully.
func Hammer(client *http.Client, targetURL string, params map[string]string, headers map[string]string) []Shadow {
	dialects := AllDialects()
	if len(dialects) < 2 {
		return nil
	}

	type outcome struct {
		dialect string
		status  int
		body    string
		err     error
	}

	var mu sync.Mutex
	var outcomes []outcome
	var wg sync.WaitGroup

	for _, d := range dialects {
		wg.Add(1)
		go func(d Dialect) {
			defer wg.Done()
			encoded := d.Encoder(params)
			req, err := http.NewRequest("POST", targetURL, strings.NewReader(encoded))
			if err != nil {
				mu.Lock()
				outcomes = append(outcomes, outcome{dialect: d.ContentType, err: err})
				mu.Unlock()
				return
			}
			req.Header.Set("Content-Type", d.ContentType)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				outcomes = append(outcomes, outcome{dialect: d.ContentType, err: err})
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
			mu.Lock()
			outcomes = append(outcomes, outcome{dialect: d.ContentType, status: resp.StatusCode, body: string(body)})
			mu.Unlock()
		}(d)
	}
	wg.Wait()

	// Compare each pair
	var shadows []Shadow
	for i := 0; i < len(outcomes); i++ {
		for j := i + 1; j < len(outcomes); j++ {
			a, b := outcomes[i], outcomes[j]
			if a.err != nil || b.err != nil {
				continue
			}
			diff := responseDiff(a.status, a.body, b.status, b.body)
			if diff != "" {
				for name := range params {
					shadows = append(shadows, Shadow{
						URL: targetURL, Param: name,
						DialectA: a.dialect, StatusA: a.status, BodyA: truncate(a.body, 500),
						DialectB: b.dialect, StatusB: b.status, BodyB: truncate(b.body, 500),
						Signature: diff,
					})
					break // one shadow per endpoint is sufficient
				}
			}
		}
	}

	return shadows
}

// ── Detection ────────────────────────────────────────────────────────────

func responseDiff(statusA int, bodyA string, statusB int, bodyB string) string {
	if statusA != statusB {
		return fmt.Sprintf("status mismatch: %d vs %d", statusA, statusB)
	}
	lenA, lenB := len(bodyA), len(bodyB)
	diff := lenA - lenB
	if diff < 0 { diff = -diff }
	if diff > 200 {
		return fmt.Sprintf("length mismatch: %d vs %d (diff=%d)", lenA, lenB, diff)
	}
	// Check for JSON vs HTML — structural difference
	if (strings.HasPrefix(bodyA, "{") && strings.HasPrefix(bodyB, "<")) ||
	   (strings.HasPrefix(bodyA, "<") && strings.HasPrefix(bodyB, "{")) {
		return "structural mismatch: JSON vs HTML"
	}
	return ""
}

// ── Helpers ──────────────────────────────────────────────────────────────

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "..."
}

var _ = bytes.Buffer{}
var _ = time.Now
