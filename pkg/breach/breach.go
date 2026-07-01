// Package breach probes OAuth 2.0, OpenID Connect, and SAML endpoints
// for common misconfigurations: open redirect, missing PKCE, implicit
// grant enabled, client-side token handling flaws, and SAML metadata leaks.
package breach

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// OAuthProbeResult holds findings from OAuth/OIDC endpoint analysis.
type OAuthProbeResult struct {
	Endpoint           string   `json:"endpoint"`
	Flow               string   `json:"flow"` // "authorization_code", "implicit", "client_credentials"
	MissingPKCE        bool     `json:"missing_pkce"`
	ImplicitGrant      bool     `json:"implicit_grant"`
	OpenRedirect       bool     `json:"open_redirect"`
	ResponseTypeIsToken bool    `json:"response_type_token"`
	Findings           []string `json:"findings"`
}

// SAMLProbeResult holds SAML-specific findings.
type SAMLProbeResult struct {
	Endpoint         string   `json:"endpoint"`
	MetadataExposed  bool     `json:"metadata_exposed"`
	SigningCertFound bool     `json:"signing_cert_found"`
	Findings         []string `json:"findings"`
}

// ── OAuth detection ───────────────────────────────────────────────────────

// OAuthProbe scans a target for OAuth/OIDC endpoints and misconfigurations.
func OAuthProbe(client *http.Client, baseURL string) []OAuthProbeResult {
	var results []OAuthProbeResult

	paths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/oauth/authorize",
		"/oauth/token",
		"/authorize",
		"/oauth2/authorize",
		"/oidc/authorize",
		"/connect/authorize",
		"/api/oauth/authorize",
	}

	for _, path := range paths {
		fullURL := join(baseURL, path)
		r := probeOAuthEndpoint(client, fullURL)
		if len(r.Findings) > 0 {
			results = append(results, r)
		}
	}

	return results
}

func probeOAuthEndpoint(client *http.Client, endpoint string) OAuthProbeResult {
	r := OAuthProbeResult{Endpoint: endpoint}

	// Step 1: Detect if endpoint exists and what flow it uses
	params := []struct {
		key   string
		val   string
	}{
		{"client_id", "sxsc_breach_test"},
		{"redirect_uri", "https://evil.com/callback"},
		{"response_type", "code"},
		{"scope", "openid profile email"},
		{"state", "sxsc_state"},
		{"nonce", "sxsc_nonce"},
	}

	u, _ := url.Parse(endpoint)
	q := u.Query()
	for _, p := range params {
		q.Set(p.key, p.val)
	}
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("User-Agent", "sxsc-breach/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return r
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	low := string(body)

	// Check if it's an OAuth endpoint
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return r
	}

	// Test: response_type=token → implicit grant enabled
	u2, _ := url.Parse(endpoint)
	q2 := u2.Query()
	q2.Set("response_type", "token")
	q2.Set("client_id", "sxsc_breach_test")
	q2.Set("redirect_uri", "https://evil.com/callback")
	u2.RawQuery = q2.Encode()
	req2, _ := http.NewRequest("GET", u2.String(), nil)
	req2.Header.Set("User-Agent", "sxsc-breach/1.0")
	resp2, err2 := client.Do(req2)
	if err2 == nil {
		resp2.Body.Close()
		if resp2.StatusCode >= 200 && resp2.StatusCode < 400 {
			r.ResponseTypeIsToken = true
			r.ImplicitGrant = true
			r.Findings = append(r.Findings, "implicit grant (response_type=token) accepted — access token exposed in URL fragment to browser history and referrer headers")
		}
	}

	// Test: code flow detected
	if strings.Contains(low, "code") || strings.Contains(low, "authorize") {
		r.Flow = "authorization_code"
		r.Findings = append(r.Findings, "authorization code flow endpoint found")

		// Check for PKCE challenge support
		if !strings.Contains(strings.ToLower(low), "code_challenge") && !strings.Contains(strings.ToLower(low), "pkce") {
			r.MissingPKCE = true
			r.Findings = append(r.Findings, "PKCE (code_challenge) not enforced — authorization code interception possible on mobile/native clients")
		}
	}

	// Test: open redirect via redirect_uri
	payloads := []string{
		"https://evil.com/callback",
		"https://evil.com/callback%40target.com",
		"https://target.com.evil.com/callback",
		"https://target.com%2F.evil.com/callback",
	}

	for _, redirectURI := range payloads {
		u3, _ := url.Parse(endpoint)
		q3 := u3.Query()
		q3.Set("client_id", "sxsc_breach_test")
		q3.Set("redirect_uri", redirectURI)
		q3.Set("response_type", "code")
		u3.RawQuery = q3.Encode()

		noRedir := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 10 * time.Second,
		}

		req3, _ := http.NewRequest("GET", u3.String(), nil)
		req3.Header.Set("User-Agent", "sxsc-breach/1.0")
		resp3, err3 := noRedir.Do(req3)
		if err3 == nil {
			resp3.Body.Close()
			loc := resp3.Header.Get("Location")
			if (resp3.StatusCode >= 300 && resp3.StatusCode < 400) &&
				(strings.Contains(loc, "evil.com") || strings.Contains(loc, "sxsc")) {
				r.OpenRedirect = true
				r.Findings = append(r.Findings, fmt.Sprintf("redirect_uri not validated — %q accepted and redirected to %q", redirectURI, loc))
				break
			}
		}
	}

	return r
}

// ── SAML detection ────────────────────────────────────────────────────────

// SAMLProbe scans for SAML metadata and configuration endpoints.
func SAMLProbe(client *http.Client, baseURL string) []SAMLProbeResult {
	var results []SAMLProbeResult

	paths := []string{
		"/saml/metadata",
		"/auth/saml/metadata",
		"/sso/saml/metadata",
		"/FederationMetadata.xml",
		"/saml2/metadata",
		"/sp/metadata",
		"/idp/shibboleth",
	}

	for _, path := range paths {
		fullURL := join(baseURL, path)
		if r := probeSAMLEndpoint(client, fullURL); len(r.Findings) > 0 {
			results = append(results, r)
		}
	}

	return results
}

func probeSAMLEndpoint(client *http.Client, endpoint string) SAMLProbeResult {
	r := SAMLProbeResult{Endpoint: endpoint}

	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("User-Agent", "sxsc-breach/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return r
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	low := strings.ToLower(string(body))

	if resp.StatusCode != 200 {
		return r
	}

	// SAML metadata indicators
	if strings.Contains(low, "entitydescriptor") || strings.Contains(low, "idpssodescriptor") {
		r.MetadataExposed = true
		r.Findings = append(r.Findings, "SAML metadata publicly accessible — reveals entity ID, endpoints, and certificate info")
	}

	// Certificate in metadata
	certRE := regexp.MustCompile(`<ds:X509Certificate>([^<]+)</ds:X509Certificate`)
	if certRE.MatchString(string(body)) {
		r.SigningCertFound = true
		r.Findings = append(r.Findings, "SAML signing certificate exposed in metadata — enables offline brute-force of key material and certificate cloning")
	}

	// SSO URL leaks
	if strings.Contains(low, "assertionconsumerservice") {
		r.Findings = append(r.Findings, "SAML assertion consumer service URL(s) exposed in metadata")
	}

	return r
}

// ── SSO Endpoint Discovery ─────────────────────────────────────────────────

// DiscoverSSO finds all SSO/identity endpoints on a target.
func DiscoverSSO(client *http.Client, baseURL string) []string {
	var found []string
	seen := make(map[string]bool)

	paths := []string{
		"/sso", "/sso/login", "/sso/metadata", "/sso/saml",
		"/auth/saml", "/auth/oauth", "/auth/oidc",
		"/login/sso", "/login/saml", "/login/oauth",
		"/idp", "/idp/shibboleth", "/idp/profile",
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/saml-configuration",
		"/FederationMetadata.xml",
	}

	// Concurrent probe
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, path := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			fullURL := join(baseURL, p)
			req, _ := http.NewRequest("GET", fullURL, nil)
			req.Header.Set("User-Agent", "sxsc-breach/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				mu.Lock()
				if !seen[p] {
					seen[p] = true
					found = append(found, fullURL)
				}
				mu.Unlock()
			}
		}(path)
	}
	wg.Wait()

	if len(found) > 0 {
		fmt.Printf("  [breach] %d SSO endpoint(s) discovered\n", len(found))
	}
	return found
}

// ── Helpers ──────────────────────────────────────────────────────────────
func join(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	path = strings.TrimPrefix(path, "/")
	return base + "/" + path
}

var _ = fmt.Sprintf
var _ = sync.Mutex{}
