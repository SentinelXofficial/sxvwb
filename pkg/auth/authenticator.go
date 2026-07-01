package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Profile defines a multi-step authentication flow.
type Profile struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Variables   map[string]string `json:"variables"` // {{USER}}, {{PASS}}, etc.
	Steps       []AuthStep   `json:"steps"`
}

// AuthStep is one step in the authentication flow.
type AuthStep struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Extract    []AuthExtract     `json:"extract,omitempty"`
	Condition  string            `json:"condition,omitempty"` // HTTP status condition (e.g. "200", "302")
}

// AuthExtract extracts values from a response for use in subsequent steps.
type AuthExtract struct {
	Name      string `json:"name"`      // variable name to set
	Source    string `json:"source"`    // "body", "header", "cookie", "json"
	Regex     string `json:"regex,omitempty"`
	JSONPath  string `json:"json_path,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`
	compiled  *regexp.Regexp
}

// Session holds the authenticated state after a profile completes.
type Session struct {
	ProfileName string
	Cookies     []*http.Cookie
	Headers     map[string]string
	Variables   map[string]string
	CookiesRaw  string // "Cookie" header format
	mu          sync.RWMutex
}

// Authenticator manages authentication profiles and sessions.
type Authenticator struct {
	profiles map[string]*Profile
	sessions map[string]*Session
	mu       sync.RWMutex
	client   *http.Client
}

// NewAuthenticator creates an authenticator with an HTTP client.
func NewAuthenticator(client *http.Client) *Authenticator {
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	return &Authenticator{
		profiles: make(map[string]*Profile),
		sessions: make(map[string]*Session),
		client:   client,
	}
}

// LoadProfile parses a JSON auth profile definition.
func (a *Authenticator) LoadProfile(r io.Reader) (*Profile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile missing name")
	}
	if len(p.Steps) == 0 {
		return nil, fmt.Errorf("profile %q has no steps", p.Name)
	}
	// Pre-compile regex extractors
	for i := range p.Steps {
		for j := range p.Steps[i].Extract {
			ext := &p.Steps[i].Extract[j]
			if ext.Regex != "" {
				re, err := regexp.Compile(ext.Regex)
				if err != nil {
					return nil, fmt.Errorf("profile %q step %d regex: %w", p.Name, i, err)
				}
				ext.compiled = re
			}
		}
	}
	return &p, nil
}

// LoadProfileString parses a JSON snippet directly.
func (a *Authenticator) LoadProfileString(jsonStr string) (*Profile, error) {
	return a.LoadProfile(strings.NewReader(jsonStr))
}

// AddProfile registers an auth profile for later use.
func (a *Authenticator) AddProfile(p *Profile) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.profiles[p.Name] = p
}

// Authenticate runs an auth profile and returns the resulting session.
// Variables like {{USER}} and {{PASS}} are substituted from the provided vars.
func (a *Authenticator) Authenticate(profileName string, vars map[string]string) (*Session, error) {
	a.mu.RLock()
	p, ok := a.profiles[profileName]
	a.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("auth profile %q not found", profileName)
	}
	return a.authenticateProfile(p, vars)
}

// AuthenticateProfile runs a profile directly (without pre-registration).
func (a *Authenticator) AuthenticateProfile(p *Profile, vars map[string]string) (*Session, error) {
	return a.authenticateProfile(p, vars)
}

func (a *Authenticator) authenticateProfile(p *Profile, vars map[string]string) (*Session, error) {
	// Merge provided vars with profile defaults
	allVars := make(map[string]string)
	for k, v := range p.Variables {
		allVars[k] = v
	}
	for k, v := range vars {
		allVars[k] = v
	}

	session := &Session{
		ProfileName: p.Name,
		Headers:     make(map[string]string),
		Variables:   make(map[string]string),
	}

	for i, step := range p.Steps {
		// Resolve variables in URL, headers, body
		resolvedURL := interpolateAuth(step.URL, allVars)
		resolvedBody := interpolateAuth(step.Body, allVars)

		var bodyReader io.Reader
		if resolvedBody != "" {
			bodyReader = strings.NewReader(resolvedBody)
		}

		method := step.Method
		if method == "" {
			method = "GET"
		}
		req, err := http.NewRequest(method, resolvedURL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", i+1, err)
		}

		// Apply stored session cookies/headers
		for _, ck := range session.Cookies {
			req.AddCookie(ck)
		}
		session.mu.RLock()
		for k, v := range session.Headers {
			req.Header.Set(k, v)
		}
		session.mu.RUnlock()

		// Apply step-specific headers
		for k, v := range step.Headers {
			req.Header.Set(k, interpolateAuth(v, allVars))
		}

		// Default headers
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "sxsc-auth/1.0")
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "*/*")
		}

		resp, err := a.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("step %d request: %w", i+1, err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()

		// Check condition if specified
		if step.Condition != "" {
			cond := interpolateAuth(step.Condition, allVars)
			if !matchCondition(resp.StatusCode, cond) {
				return nil, fmt.Errorf("step %d: expected condition %q, got HTTP %d", i+1, cond, resp.StatusCode)
			}
		}

		// Store response cookies
		for _, ck := range resp.Cookies() {
			session.mu.Lock()
			session.Cookies = append(session.Cookies, ck)
			session.mu.Unlock()
		}

		// Extract variables from response
		for _, ext := range step.Extract {
			val := extractValue(resp, string(respBody), ext)
			if val != "" {
				allVars[ext.Name] = val
				session.mu.Lock()
				session.Variables[ext.Name] = val
				session.mu.Unlock()
			}
		}
	}

	// Build Cookie header
	var cookieParts []string
	for _, ck := range session.Cookies {
		cookieParts = append(cookieParts, ck.Name+"="+ck.Value)
	}
	session.CookiesRaw = strings.Join(cookieParts, "; ")

	fmt.Printf("  \033[32m[AUTH] Profile %q authenticated — %d cookies, %d variables\033[0m\n",
		p.Name, len(session.Cookies), len(session.Variables))

	return session, nil
}

// ── Utilities ─────────────────────────────────────────────────────────────

func interpolateAuth(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func matchCondition(status int, cond string) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return true
	}
	// Support "200", "302", "2xx", "3xx", "200-399"
	if strings.HasSuffix(cond, "xx") {
		prefix := cond[:len(cond)-2]
		return fmt.Sprintf("%d", status)[:1] == prefix
	}
	if strings.Contains(cond, "-") {
		parts := strings.SplitN(cond, "-", 2)
		var lo, hi int
		fmt.Sscanf(parts[0], "%d", &lo)
		fmt.Sscanf(parts[1], "%d", &hi)
		return status >= lo && status <= hi
	}
	var expected int
	fmt.Sscanf(cond, "%d", &expected)
	return status == expected
}

func extractValue(resp *http.Response, body string, ext AuthExtract) string {
	switch ext.Source {
	case "header":
		if ext.HeaderName != "" {
			return resp.Header.Get(ext.HeaderName)
		}
	case "cookie":
		for _, ck := range resp.Cookies() {
			if strings.EqualFold(ck.Name, ext.CookieName) {
				return ck.Value
			}
		}
	case "json":
		if ext.JSONPath != "" {
			// Simple JSON path: $.token, $.data.access_token
			return simpleJSONPath(body, ext.JSONPath)
		}
	case "body", "":
		if ext.compiled != nil {
			matches := ext.compiled.FindStringSubmatch(body)
			if len(matches) >= 2 {
				return matches[1]
			}
		}
	}
	return ""
}

// simpleJSONPath implements a basic `$.key.subkey` extractor without a full JSONPath engine.
func simpleJSONPath(body, path string) string {
	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return ""
	}
	path = strings.TrimPrefix(path, "$")
	parts := strings.Split(strings.TrimPrefix(path, "."), ".")
	current := data
	for _, part := range parts {
		if part == "" {
			continue
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current = m[part]
	}
	if s, ok := current.(string); ok {
		return s
	}
	// Return JSON representation for non-string values
	if current != nil {
		b, _ := json.Marshal(current)
		return string(b)
	}
	return ""
}

// ── Built-in Auth Profile Templates ──────────────────────────────────────

// BuiltinFormLogin returns a generic form-based login profile.
func BuiltinFormLogin(loginURL, username, password string) *Profile {
	return &Profile{
		Name:        "form-login",
		Description: "Generic form-based login with username/password",
		Variables: map[string]string{
			"USER": username,
			"PASS": password,
		},
		Steps: []AuthStep{
			{
				Method: "GET",
				URL:    loginURL,
				Extract: []AuthExtract{
					{
						Name:   "csrf",
						Source: "body",
						Regex:  `name=["'](?:csrf|_token|authenticity_token)["']\s+value=["']([^"']+)["']`,
					},
				},
			},
			{
				Method:  "POST",
				URL:     loginURL,
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:    "username={{USER}}&password={{PASS}}&csrf={{csrf}}",
				Condition: "302",
				Extract: []AuthExtract{
					{
						Name:      "session",
						Source:    "cookie",
						CookieName: "session",
					},
				},
			},
		},
	}
}

// BuiltinBearerToken returns a profile that just sets a Bearer token header.
func BuiltinBearerToken(token string) *Profile {
	return &Profile{
		Name:        "bearer-token",
		Description: "Static Bearer token for API authentication",
		Variables:   map[string]string{"TOKEN": token},
		Steps: []AuthStep{
			{
				Method:  "GET",
				URL:     "https://httpbin.org/bearer",
				Headers: map[string]string{"Authorization": "Bearer {{TOKEN}}"},
				Condition: "200",
			},
		},
	}
}

// BuiltinOAuth2ClientCredentials returns an OAuth2 client_credentials profile.
func BuiltinOAuth2ClientCredentials(tokenURL, clientID, clientSecret string) *Profile {
	return &Profile{
		Name:        "oauth2-client-credentials",
		Description: "OAuth2 client credentials grant",
		Variables: map[string]string{
			"TOKEN_URL":     tokenURL,
			"CLIENT_ID":     clientID,
			"CLIENT_SECRET": clientSecret,
		},
		Steps: []AuthStep{
			{
				Method:  "POST",
				URL:     "{{TOKEN_URL}}",
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:    "grant_type=client_credentials&client_id={{CLIENT_ID}}&client_secret={{CLIENT_SECRET}}",
				Extract: []AuthExtract{
					{
						Name:     "access_token",
						Source:   "json",
						JSONPath: "$.access_token",
					},
				},
			},
		},
	}
}

// Ensure imports are used
var _ = url.Parse
var _ = time.Now
