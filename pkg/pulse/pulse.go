// Package pulse manages authentication session lifecycle across a scan.
// It detects session expiry (redirect to login, 401/403 responses, body
// changes), re-authenticates using a stored profile, and resumes scanning.
// This enables long-running thorough scans without manual intervention.
package pulse

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Beat tracks one session's health and renewal state.
type Beat struct {
	Name       string
	Target     string
	Cookies    []*http.Cookie
	Headers    map[string]string
	Baseline   *Baseline // snapshot of a healthy session response

	renewFn    func() (*Beat, error) // auth profile to re-login
	mu         sync.RWMutex
	expiryHits int
	lastRenew  time.Time
}

// Baseline captures the healthy-state response signature.
type Baseline struct {
	Status    int
	BodyLen   int
	BodyHash  string // simple fingerprint
	Redirects bool
	Location  string
}

// ── Factory ──────────────────────────────────────────────────────────────

// New creates a fresh session Beat. Provide a renew function that can
// re-authenticate and return a new Beat when the session expires.
func New(name, target string, cookies []*http.Cookie, headers map[string]string, renewFn func() (*Beat, error)) *Beat {
	return &Beat{
		Name:    name,
		Target:  target,
		Cookies: cookies,
		Headers: headers,
		renewFn: renewFn,
	}
}

// ── Baseline capture ─────────────────────────────────────────────────────

// Snapshot captures the healthy-state baseline. Call after authentication.
func (b *Beat) Snapshot(client *http.Client) error {
	resp, err := b.doRequest(client, b.Target)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	b.mu.Lock()
	defer b.mu.Unlock()
	b.Baseline = &Baseline{
		Status:    resp.StatusCode,
		BodyLen:   len(body),
		BodyHash:  quickHash(string(body)),
		Redirects: resp.StatusCode >= 300 && resp.StatusCode < 400,
		Location:  resp.Header.Get("Location"),
	}
	return nil
}

// ── Health check ─────────────────────────────────────────────────────────

// Alive returns true if the session is still valid. It sends a probe request
// and compares against the baseline signature.
func (b *Beat) Alive(client *http.Client) bool {
	b.mu.RLock()
	base := b.Baseline
	b.mu.RUnlock()
	if base == nil {
		return true // no baseline yet, assume alive
	}

	resp, err := b.doRequest(client, b.Target)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Dead if redirected to login
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if isLoginURL(loc) {
			return false
		}
	}

	// Dead if we got 401/403
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}

	// Dead if body length changed dramatically (session replaced by login form)
	bodyLen := len(body)
	if base.BodyLen > 0 {
		ratio := float64(bodyLen) / float64(base.BodyLen)
		if ratio < 0.3 || ratio > 3.0 {
			return false
		}
	}

	return true
}

// ── Auto-renewal ─────────────────────────────────────────────────────────

// Stay ensures the session is alive. If not, it renews via the auth profile
// and re-snapshots the baseline. Returns the renewed Beat (or same if alive).
func (b *Beat) Stay(client *http.Client) (*Beat, error) {
	if b.Alive(client) {
		return b, nil
	}

	if b.renewFn == nil {
		return b, fmt.Errorf("session %q expired and no renew function configured", b.Name)
	}

	b.expiryHits++
	now := time.Now()
	if !b.lastRenew.IsZero() && now.Sub(b.lastRenew) < 5*time.Second {
		return b, fmt.Errorf("session %q: renewal loop detected — too frequent (%v)", b.Name, now.Sub(b.lastRenew))
	}
	b.lastRenew = now

	fmt.Printf("  [pulse] Session %q expired — re-authenticating (expiry #%d)\n", b.Name, b.expiryHits)
	newBeat, err := b.renewFn()
	if err != nil {
		return b, fmt.Errorf("session %q renewal failed: %w", b.Name, err)
	}

	// Re-snapshot
	if err := newBeat.Snapshot(client); err != nil {
		return newBeat, fmt.Errorf("renewed session snapshot: %w", err)
	}

	fmt.Printf("  [pulse] Session %q renewed successfully\n", newBeat.Name)
	return newBeat, nil
}

// ── Round trip ───────────────────────────────────────────────────────────

// Round sends a request through the session. If the session is dead,
// it renews and retries once. Returns the final response.
func (b *Beat) Round(client *http.Client, method, rawURL string, body io.Reader) (*http.Response, error) {
	resp, err := b.doRequestWithBody(client, method, rawURL, body)
	if err != nil {
		return resp, err
	}

	// Check if the response indicates session death
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		if loc := resp.Header.Get("Location"); isLoginURL(loc) {
			// Try renewal
			newBeat, renewErr := b.Stay(client)
			if renewErr != nil {
				return resp, nil // return original response if renewal fails
			}
			// Retry with renewed session — copy data fields (not the mutex)
			b.mu.Lock()
			b.Cookies = newBeat.Cookies
			b.Headers = newBeat.Headers
			b.Baseline = newBeat.Baseline
			b.expiryHits = newBeat.expiryHits
			b.lastRenew = newBeat.lastRenew
			b.mu.Unlock()
			resp.Body.Close()
			return b.doRequestWithBody(client, method, rawURL, body)
		}
	}

	return resp, nil
}

// ── Internal ─────────────────────────────────────────────────────────────

func (b *Beat) doRequest(client *http.Client, rawURL string) (*http.Response, error) {
	return b.doRequestWithBody(client, "GET", rawURL, nil)
}

func (b *Beat) doRequestWithBody(client *http.Client, method, rawURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, err
	}

	b.mu.RLock()
	for _, ck := range b.Cookies {
		req.AddCookie(ck)
	}
	for k, v := range b.Headers {
		req.Header.Set(k, v)
	}
	b.mu.RUnlock()

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "sxsc-pulse/1.0")
	}

	return client.Do(req)
}

func isLoginURL(loc string) bool {
	lower := strings.ToLower(loc)
	for _, kw := range []string{"login", "signin", "sign_in", "auth", "sso", "oauth", "session/new"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func quickHash(s string) string {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return fmt.Sprintf("%08x", h)
}

// ── Cookie jar wrapper ───────────────────────────────────────────────────

// Jar creates an http.CookieJar pre-filled with the session cookies.
func (b *Beat) Jar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(b.Target)
	b.mu.RLock()
	jar.SetCookies(u, b.Cookies)
	b.mu.RUnlock()
	return jar
}

// CookieHeader returns the Cookie header value for the session.
func (b *Beat) CookieHeader() string {
	var parts []string
	b.mu.RLock()
	for _, ck := range b.Cookies {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	b.mu.RUnlock()
	return strings.Join(parts, "; ")
}

var _ = io.ReadAll
