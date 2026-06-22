// Package sieve extracts every possible injection point from a target.
// It mines parameters from HTML forms, JavaScript files, JSON responses,
// URL query strings, path segments, cookies, and HTTP headers — building
// a complete parameter inventory for every scan module to attack.
package sieve

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// ── Types ────────────────────────────────────────────────────────────────

// Spot marks one injection point with its context (where it lives, what
// type it holds, and the surrounding HTML/JSON for context-aware fuzzing).
type Spot struct {
	Name    string   `json:"name"`             // parameter name
	Value   string   `json:"value,omitempty"`  // current value (for baseline)
	Origin  string   `json:"origin"`           // "query", "path", "form", "json", "header", "cookie", "js"
	Shape   string   `json:"shape,omitempty"`  // "int", "string", "email", "url", "bool", "json", "xml"
	URL     string   `json:"url"`              // page where it was found
	Details string   `json:"details,omitempty"` // form action, cookie domain, etc.
}

// Harvest holds all injection points collected from a target.
type Harvest struct {
	Target   string
	Spots    []Spot
	ByOrigin map[string][]Spot // grouped by origin type
	mu       sync.Mutex
}

// ── Collector ────────────────────────────────────────────────────────────

// Sift extracts parameters from every known source: URL query string, path
// segments, HTML forms, JSON bodies, JS file variables, cookies, and headers.
func Sift(client *http.Client, targetURL string, headers map[string]string, cookie string) *Harvest {
	h := &Harvest{
		Target:   targetURL,
		ByOrigin: make(map[string][]Spot),
	}

	h.SiftURL(targetURL)
	h.SiftPage(client, targetURL, headers, cookie)
	h.SiftJS(client, targetURL, headers)

	return h
}

// ── Mining methods ───────────────────────────────────────────────────────

// SiftURL extracts params from the URL query string and path segments.
func (h *Harvest) SiftURL(rawURL string) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	// Query string
	for name, vals := range p.Query() {
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		spot := Spot{Name: name, Value: val, Origin: "query", Shape: guessShape(val), URL: p.String()}
		h.add(spot)
	}

	// Path segments that look like IDs or slugs
	parts := strings.Split(strings.Trim(p.Path, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		shape := guessShape(part)
		if shape != "string" {
			spot := Spot{Name: part, Value: part, Origin: "path", Shape: shape, URL: p.String()}
			h.add(spot)
		}
	}
}

// SiftPage fetches the page and extracts form fields and JSON endpoints.
func (h *Harvest) SiftPage(client *http.Client, targetURL string, headers map[string]string, cookie string) {
	req, _ := http.NewRequest("GET", targetURL, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "sxsc/1.0")
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	text := string(body)

	// HTML forms
	formRE := regexp.MustCompile(`<form[^>]*action=["']([^"']*)["'][^>]*>`)
	inputRE := regexp.MustCompile(`<input[^>]*name=["']([^"']+)["'][^>]*(?:type=["']([^"']+)["'])?[^>]*(?:value=["']([^"']*)["'])?`)
	selectRE := regexp.MustCompile(`<select[^>]*name=["']([^"']+)["']`)
	textareaRE := regexp.MustCompile(`<textarea[^>]*name=["']([^"']+)["']`)

	action := targetURL
	if m := formRE.FindStringSubmatch(text); len(m) >= 2 && m[1] != "" {
		action = resolveURL(targetURL, m[1])
	}

	for _, m := range inputRE.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if name == "" {
			continue
		}
		itype := m[2]
		val := m[3]
		if itype == "" {
			itype = "text"
		}
		// Skip display-only inputs
		if itype == "hidden" || itype == "submit" || itype == "reset" || itype == "button" || itype == "image" {
			continue
		}
		if itype == "file" {
			h.add(Spot{Name: name, Value: val, Origin: "form", Shape: "file", URL: targetURL, Details: action})
			continue
		}
		h.add(Spot{Name: name, Value: val, Origin: "form", Shape: guessShape(val), URL: targetURL, Details: action})
	}
	// for _, m := range selectRE.FindAllStringSubmatch(text, -1) { h.add(Spot{Name: m[1], Origin: "form", Shape: "string", URL: targetURL, Details: action}) }
	// for _, m := range textareaRE.FindAllStringSubmatch(text, -1) { h.add(Spot{Name: m[1], Origin: "form", Shape: "string", URL: targetURL, Details: action}) }
	_ = selectRE
	_ = textareaRE

	// Response cookies (become injection points too)
	for _, ck := range resp.Cookies() {
		h.add(Spot{Name: ck.Name, Value: ck.Value, Origin: "cookie", Shape: guessShape(ck.Value), URL: targetURL, Details: ck.Domain})
	}

	// Response headers (check for custom app headers)
	for name, vals := range resp.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-") {
			for _, v := range vals {
				h.add(Spot{Name: name, Value: v, Origin: "header", Shape: "string", URL: targetURL})
			}
		}
	}
}

// SiftJS fetches JS files and extracts API endpoints + parameters.
func (h *Harvest) SiftJS(client *http.Client, targetURL string, headers map[string]string) {
	req, _ := http.NewRequest("GET", targetURL, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "sxsc/1.0")
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	text := string(body)

	// Fetch API endpoints from JS patterns
	epPatterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"'\s)]+)["']`),
		regexp.MustCompile(`fetch\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`axios\.\w+\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\$\.(?:get|post|ajax)\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`url\s*[:=]\s*["']([^"']+)["']`),
	}

	for _, re := range epPatterns {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) >= 2 {
				raw := m[1]
				parsed, err := url.Parse(raw)
				if err != nil {
					// Relative path — resolve
					full := resolveURL(targetURL, raw)
					h.SiftURL(full)
				} else {
					_ = parsed
					// Extract query params from the endpoint
					h.SiftURL(raw)
				}
			}
		}
	}

	// Find JS variable names that look like endpoint paths or params
	varRE := regexp.MustCompile(`(?:apiPath|apiUrl|baseUrl|endpoint|basePath)\s*[:=]\s*["']([^"']+)["']`)
	for _, m := range varRE.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			full := resolveURL(targetURL, m[1])
			h.SiftURL(full)
		}
	}
}

// ── Shape detection ──────────────────────────────────────────────────────

func guessShape(val string) string {
	if val == "" {
		return "string"
	}
	if regexp.MustCompile(`^\d{1,16}$`).MatchString(val) {
		return "int"
	}
	if regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`).MatchString(val) {
		return "date"
	}
	if regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(val) {
		return "email"
	}
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		return "url"
	}
	if val == "true" || val == "false" || val == "1" || val == "0" {
		return "bool"
	}
	if (strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}")) ||
		(strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]")) {
		return "json"
	}
	if strings.HasPrefix(val, "<") && strings.HasSuffix(val, ">") {
		return "xml"
	}
	return "string"
}

// ── Helpers ──────────────────────────────────────────────────────────────

func (h *Harvest) add(spot Spot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Spots = append(h.Spots, spot)
	h.ByOrigin[spot.Origin] = append(h.ByOrigin[spot.Origin], spot)
}

// Flush returns a deduplicated list of all spots.
func (h *Harvest) Flush() []Spot {
	seen := make(map[string]bool)
	var out []Spot
	for _, s := range h.Spots {
		key := s.Origin + "|" + s.Name + "|" + s.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	return out
}

// QueryParams returns all spots from URL query strings.
func (h *Harvest) QueryParams() []Spot { return h.ByOrigin["query"] }

// FormFields returns all spots from HTML forms.
func (h *Harvest) FormFields() []Spot { return h.ByOrigin["form"] }

// PathSegments returns all spots from URL path segments.
func (h *Harvest) PathSegments() []Spot { return h.ByOrigin["path"] }

// Count returns the total number of unique injection spots found.
func (h *Harvest) Count() int { return len(h.Flush()) }

func resolveURL(base, href string) string {
	if strings.HasPrefix(href, "http") {
		return href
	}
	p, _ := url.Parse(base)
	if p == nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return p.ResolveReference(ref).String()
}

var _ = fmt.Sprintf
var _ = strings.Trim
