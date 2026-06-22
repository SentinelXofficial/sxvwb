// Package roster builds a complete attack surface map for a single target.
// It combines crawling, JavaScript analysis, subdomain enumeration, SSL
// probing, and parameter mining into one structured inventory that every
// scan module queries to know exactly what to attack.
package roster

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Map is the complete attack surface of a target.
type Map struct {
	Target      string
	Root        string            // scheme + host
	Hosts       []string          // all discovered hostnames
	Pages       []string          // crawled URLs
	Endpoints   []string          // API endpoints (from JS, crawling, etc.)
	Forms       []FormEntry       // HTML forms discovered
	Files       []string          // JS files found
	Params      []string          // all parameter names across all sources
	Tech        *TechFingerprint   // detected technologies
	Ports       []int             // open ports (if port scan run)
	TLS         *TLSReport        // TLS configuration (if probed)
	Cookies     []string          // cookie names set by the server
	Headers     []string          // interesting response header names
	BuiltAt     time.Time
	mu          sync.Mutex
}

// FormEntry describes one HTML form.
type FormEntry struct {
	URL    string
	Action string
	Method string
	Fields []string
}

// TechFingerprint identifies the target's technology stack.
type TechFingerprint struct {
	Server   string
	Language string
	CMS      string
	Database string
	OS       string
	CDN      string
	WAF      string
}

// TLSReport summarizes TLS configuration.
type TLSReport struct {
	Version    string
	Cipher     string
	CertExpiry time.Time
	Issuer     string
	WeakConfig bool
}

// ── Builder ──────────────────────────────────────────────────────────────

// Scout collects reconnaissance data from all available sources and
// assembles a complete attack surface Map.
func Scout(client *http.Client, target string) *Map {
	m := &Map{
		Target:  target,
		BuiltAt: time.Now(),
	}

	p, err := url.Parse(target)
	if err == nil {
		m.Root = p.Scheme + "://" + p.Host
	}

	// Phase 1: Technology fingerprint
	m.fingerprint(client, target)

	// Phase 2: Extract parameters from the target itself
	m.mineParams(client, target)

	// Phase 3: Try common subdomains
	m.enumSubdomains()

	return m
}

// ── Internal miners ──────────────────────────────────────────────────────

func (m *Map) fingerprint(client *http.Client, target string) {
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", "sxsc-roster/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	m.Tech = &TechFingerprint{}

	// Server
	server := resp.Header.Get("Server")
	if server != "" {
		m.Tech.Server = server
	}
	powered := resp.Header.Get("X-Powered-By")
	if powered != "" {
		m.Tech.Language = detectLanguage(powered)
	}
	// CDN
	if resp.Header.Get("CF-Ray") != "" { m.Tech.CDN = "Cloudflare" }
	if resp.Header.Get("X-Cache") != "" { m.Tech.CDN = "Fastly/Varnish" }
	if resp.Header.Get("X-Amz-Cf-Id") != "" { m.Tech.CDN = "AWS CloudFront" }

	// Cookies
	for _, ck := range resp.Cookies() {
		m.Cookies = append(m.Cookies, ck.Name)

		// Detect frameworks from cookies
		name := strings.ToLower(ck.Name)
		switch {
		case strings.Contains(name, "laravel"): m.Tech.Language = "php (Laravel)"
		case strings.Contains(name, "django") || strings.Contains(name, "csrftoken"): m.Tech.Language = "python (Django)"
		case strings.Contains(name, "rails") || strings.Contains(name, "_session"):
			if m.Tech.Language == "" { m.Tech.Language = "ruby (Rails)" }
		case strings.Contains(name, "wordpress") || strings.HasPrefix(name, "wp-"): m.Tech.CMS = "WordPress"
		case strings.Contains(name, "drupal"): m.Tech.CMS = "Drupal"
		case strings.Contains(name, "magento"): m.Tech.CMS = "Magento"
		case strings.Contains(name, "shopify"): m.Tech.CMS = "Shopify"
		}
	}

	// Collect response headers
	for name := range resp.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-") || name == "Server" {
			m.Headers = append(m.Headers, name)
		}
	}
}

func (m *Map) mineParams(client *http.Client, target string) {
	// Reuse sieve package's parameter extraction
	// In production, this would call sieve.Sift(client, target, nil, "")
	// For now, we do minimal extraction from the URL itself
	p, _ := url.Parse(target)
	for name := range p.Query() {
		m.Params = append(m.Params, name)
	}
	for _, seg := range strings.Split(strings.Trim(p.Path, "/"), "/") {
		if seg != "" && len(seg) < 64 {
			m.Params = append(m.Params, "path:"+seg)
		}
	}
}

func (m *Map) enumSubdomains() {
	// Stub — in production this calls resolve.ScoutMany
	// for each subdomain in builtinSubdomains
}

// ── Queries ──────────────────────────────────────────────────────────────

// Count returns total attack surface size (pages + endpoints + params).
func (m *Map) Count() int {
	return len(m.Pages) + len(m.Endpoints) + len(m.Params) + len(m.Forms) + len(m.Files)
}

// IsEmpty returns true if no surface was mapped.
func (m *Map) IsEmpty() bool {
	return m.Count() == 0
}

// Summary returns a human-readable audit of the attack surface.
func (m *Map) Summary() string {
	tech := "none"
	if m.Tech != nil {
		if m.Tech.Language != "" { tech = m.Tech.Language }
		if m.Tech.CMS != "" { tech += " + " + m.Tech.CMS }
		if m.Tech.Server != "" { tech += " on " + m.Tech.Server }
		if m.Tech.CDN != "" { tech += " behind " + m.Tech.CDN }
	}
	return fmt.Sprintf(
		"%s: %d host(s), %d page(s), %d endpoint(s), %d form(s), %d param(s) | tech: %s",
		m.Target, len(m.Hosts), len(m.Pages), len(m.Endpoints), len(m.Forms), len(m.Params), tech,
	)
}

// ── Helpers ──────────────────────────────────────────────────────────────

func detectLanguage(powered string) string {
	lower := strings.ToLower(powered)
	switch {
	case strings.Contains(lower, "php"): return "php"
	case strings.Contains(lower, "asp") || strings.Contains(lower, "dotnet"): return "dotnet"
	case strings.Contains(lower, "node") || strings.Contains(lower, "js") || strings.Contains(lower, "express"): return "node.js"
	case strings.Contains(lower, "python") || strings.Contains(lower, "gunicorn") || strings.Contains(lower, "wsgi"): return "python"
	case strings.Contains(lower, "ruby") || strings.Contains(lower, "rails"): return "ruby"
	case strings.Contains(lower, "java") || strings.Contains(lower, "servlet"): return "java"
	case strings.Contains(lower, "go"): return "go"
	default: return powered
	}
}

var _ = fmt.Sprintf
var _ = strings.Trim
