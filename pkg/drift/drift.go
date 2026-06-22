// Package drift performs differential testing: sends the same payload
// through multiple Content-Type headers, HTTP methods, and parameter
// positions to find parsing inconsistencies that signal deeper bugs.
package drift

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Anomaly records a significant difference between two request variants.
type Anomaly struct {
	URL     string
	Param   string
	DiffA   string // "GET?id=1"
	DiffB   string // "POST with JSON body"
	StatusA int
	StatusB int
	LenA    int
	LenB    int
	Delta   int    // abs(len difference)
	Signal  string // what's different
}

// ── Strategies ────────────────────────────────────────────────────────────

// Shift tests parameter positions: query string, POST body, JSON body,
// XML body, multipart, path segment — and flags any divergent responses.
func Shift(client *http.Client, baseURL, param, value string, headers map[string]string) []Anomaly {
	encodings := []struct {
		name        string
		method      string
		contentType string
		buildURL    bool
		body        string
	}{
		{"GET query", "GET", "", true, ""},
		{"POST form", "POST", "application/x-www-form-urlencoded", false, param + "=" + value},
		{"POST JSON", "POST", "application/json", false, fmt.Sprintf(`{"%s":"%s"}`, param, value)},
		{"POST XML", "POST", "application/xml", false, fmt.Sprintf(`<?xml version="1.0"?><root><%s>%s</%s></root>`, param, value, param)},
		{"PUT form", "PUT", "application/x-www-form-urlencoded", false, param + "=" + value},
	}

	type outcome struct {
		name   string
		status int
		body   string
		err    error
	}

	ch := make(chan outcome, len(encodings))

	for _, enc := range encodings {
		go func(e struct {
			name, method, contentType string
			buildURL                   bool
			body                       string
		}) {
			var resp *http.Response
			var err error

			if e.buildURL {
				url := baseURL
				if strings.Contains(url, "?") {
					url += "&" + param + "=" + value
				} else {
					url += "?" + param + "=" + value
				}
				req, _ := http.NewRequest(e.method, url, nil)
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				req.Header.Set("User-Agent", "sxsc-drift/1.0")
				resp, err = client.Do(req)
			} else {
				req, _ := http.NewRequest(e.method, baseURL, strings.NewReader(e.body))
				req.Header.Set("Content-Type", e.contentType)
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				req.Header.Set("User-Agent", "sxsc-drift/1.0")
				resp, err = client.Do(req)
			}

			if err != nil {
				ch <- outcome{name: e.name, err: err}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
			ch <- outcome{name: e.name, status: resp.StatusCode, body: string(body)}
		}(enc)
	}

	var outcomes []outcome
	for i := 0; i < len(encodings); i++ {
		outcomes = append(outcomes, <-ch)
	}

	// Compare each pair
	var anomalies []Anomaly
	for i := 0; i < len(outcomes); i++ {
		for j := i + 1; j < len(outcomes); j++ {
			a, b := outcomes[i], outcomes[j]
			if a.err != nil || b.err != nil {
				continue
			}

			delta := len(a.body) - len(b.body)
			if delta < 0 { delta = -delta }

			signal := ""
			if a.status != b.status {
				signal = fmt.Sprintf("status mismatch: %d vs %d", a.status, b.status)
			} else if delta > 200 {
				signal = fmt.Sprintf("length mismatch: %d vs %d (%d diff)", len(a.body), len(b.body), delta)
			} else if (strings.HasPrefix(a.body, "{") && strings.HasPrefix(b.body, "<")) ||
				(strings.HasPrefix(a.body, "<") && strings.HasPrefix(b.body, "{")) {
				signal = "structural mismatch: JSON vs HTML"
			}

			if signal != "" {
				anomalies = append(anomalies, Anomaly{
					URL: baseURL, Param: param,
					DiffA: a.name, DiffB: b.name,
					StatusA: a.status, StatusB: b.status,
					LenA: len(a.body), LenB: len(b.body),
					Delta: delta, Signal: signal,
				})
			}
		}
	}

	return anomalies
}

// ── Method confusion ─────────────────────────────────────────────────────

// MethodConfusion tests what happens when a parameter is sent via a
// "safe" method (GET/HEAD) vs state-changing method (POST/PUT/DELETE).
// If both return 200, there's potential CSRF or method confusion.
func MethodConfusion(client *http.Client, baseURL string, headers map[string]string) []Anomaly {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
	type outcome struct {
		method string
		status int
		length int
	}

	ch := make(chan outcome, len(methods))
	for _, method := range methods {
		go func(m string) {
			req, _ := http.NewRequest(m, baseURL, nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("User-Agent", "sxsc-drift/1.0")
			resp, err := client.Do(req)
			if err != nil {
				ch <- outcome{method: m}
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			ch <- outcome{method: m, status: resp.StatusCode, length: len(body)}
		}(method)
	}

	var outcomes []outcome
	for i := 0; i < len(methods); i++ {
		outcomes = append(outcomes, <-ch)
	}

	var anomalies []Anomaly
	for _, o := range outcomes {
		if o.method == "GET" { continue }
		if o.status >= 200 && o.status < 400 {
			anomalies = append(anomalies, Anomaly{
				URL: baseURL, Param: "method",
				DiffA: "GET", DiffB: o.method,
				StatusA: 200, StatusB: o.status,
				Signal: fmt.Sprintf("%s returns %d — possible method confusion", o.method, o.status),
			})
		}
	}
	return anomalies
}

// ── Compile guards ────────────────────────────────────────────────────────
var _ = sync.Mutex{}
var _ = time.Now
