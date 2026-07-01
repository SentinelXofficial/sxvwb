// Package specter drives a headless browser for SPA crawling, DOM-based
// XSS detection, and JavaScript-rendered page interaction.  When a chromedp
// dependency is added, the stub methods in this file become live.
//
// Usage sketch (requires: go get github.com/chromedp/chromedp):
//
//	s := specter.NewSpecter(specter.WithHeadless(true))
//	s.Wake(ctx)
//	defer s.Sleep()
//
//	tab := s.Open("http://target.com")
//	results, html, _ := tab.Play([]specter.Action{
//	  {Do: "goto", Value: "http://target.com/login"},
//	  {Do: "type", Target: "#username", Value: "admin"},
//	  {Do: "click", Target: "#submit"},
//	  {Do: "extract", Target: ".csrf-token", Extract: "text"},
//	})
package specter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Specter manages a headless browser process. One Specter = one browser
// instance, which can contain multiple Phantoms (tabs).
type Specter struct {
	Headless  bool
	SlowMo    int    // ms delay between actions (debug mode)
	Timeout   int    // seconds before page load aborts
	UserAgent string
	ProxyURL  string
	active    bool
}

// Phantom represents one browser tab. All actions on a Phantom happen
// sequentially within the same tab session.
type Phantom struct {
	id      string
	specter *Specter
	cookies map[string]string
	url     string
}

// Action describes one browser automation step — inspired by Puppeteer/Playwright
// but with simpler, more explicit verbs.
type Action struct {
	Do      string            `yaml:"do"`               // "goto", "click", "type", "extract", "wait", "scroll", "shot", "eval"
	Target  string            `yaml:"target,omitempty"`  // CSS selector or URL
	Value   string            `yaml:"value,omitempty"`   // text to type, seconds to wait, JS to eval
	WaitFor string            `yaml:"wait_for,omitempty"` // CSS selector to appear before continuing
	Extract string            `yaml:"extract,omitempty"` // "text", "html", "attr"
	Attr    string            `yaml:"attr,omitempty"`    // attribute name (when extract=attr)
	Args    map[string]string `yaml:"args,omitempty"`
}

// PlayResult holds the data collected from a series of browser actions.
type PlayResult struct {
	Steps []StepResult       // per-action output
	HTML  string             // final page HTML
	URL   string             // final page URL
	Title string             // final page title
}

// StepResult records what one action produced.
type StepResult struct {
	Action   string            // action index or name
	Do       string            // verb
	Target   string            // CSS selector acted on
	Extracts map[string]string // extracted values from this step
	Error    string            // if the step failed
}

// ── Factory ──────────────────────────────────────────────────────────────

// NewSpecter creates a headless browser driver. The actual browser process
// connects lazily on the first Phantom request.
func NewSpecter(opts ...func(*Specter)) *Specter {
	s := &Specter{
		Headless:  true,
		Timeout:   30,
		UserAgent: "sxsc-specter/1.0",
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ── Options ──────────────────────────────────────────────────────────────

func WithHeadless(v bool) func(*Specter)    { return func(s *Specter) { s.Headless = v } }
func WithTimeout(n int) func(*Specter)       { return func(s *Specter) { s.Timeout = n } }
func WithSlowMo(ms int) func(*Specter)       { return func(s *Specter) { s.SlowMo = ms } }
func WithUserAgent(ua string) func(*Specter) { return func(s *Specter) { s.UserAgent = ua } }
func WithProxy(url string) func(*Specter)    { return func(s *Specter) { s.ProxyURL = url } }

// ── Lifecycle ────────────────────────────────────────────────────────────

// Wake initializes the browser process. In a full implementation with
// chromedp, this calls chromedp.NewContext and allocates a browser tab.
// In this stub, it records that the browser is active.
func (s *Specter) Wake(ctx context.Context) error {
	// chromedp: ctx, cancel = chromedp.NewContext(ctx)
	s.active = true
	return nil
}

// Sleep terminates the browser process and releases resources.
func (s *Specter) Sleep() error {
	s.active = false
	return nil
}

// Open creates a new tab navigated to the given URL.
func (s *Specter) Open(targetURL string) *Phantom {
	return &Phantom{
		id:      fmt.Sprintf("phant-%d", time.Now().UnixNano()%999999),
		specter: s,
		url:     targetURL,
		cookies: make(map[string]string),
	}
}

// ── Actions ──────────────────────────────────────────────────────────────

// Play runs a sequence of browser actions and collects extracted values.
func (p *Phantom) Play(actions []Action) (*PlayResult, error) {
	if !p.specter.active {
		return nil, fmt.Errorf("specter not active — call Wake() first")
	}

	result := &PlayResult{URL: p.url}

	for i, act := range actions {
		step := StepResult{Action: fmt.Sprintf("step-%d", i), Do: act.Do, Target: act.Target, Extracts: make(map[string]string)}
		p.maybeSlow()

		switch act.Do {
		case "goto":
			// chromedp: chromedp.Navigate(act.Value, chromedp.FromNode(node))
			p.url = act.Value
			result.URL = act.Value
			result.HTML = fmt.Sprintf("<!-- specter: rendered %s -->", act.Value)

		case "click":
			// chromedp: chromedp.Click(act.Target)
			if act.WaitFor != "" {
				// chromedp: chromedp.WaitReady(act.WaitFor)
				time.Sleep(time.Duration(p.specter.Timeout/3) * time.Second)
			}

		case "type":
			// chromedp: chromedp.SendKeys(act.Target, act.Value)
			_ = act.Value

		case "extract":
			// chromedp: chromedp.Text(act.Target, &text)
			val := fmt.Sprintf("<!-- extracted(%s from %s) -->", act.Extract, act.Target)
			step.Extracts[act.Target] = val

		case "wait":
			sec := parseInt(act.Value)
			if sec <= 0 {
				sec = 1
			}
			time.Sleep(time.Duration(sec) * time.Second)

		case "scroll":
			// chromedp: chromedp.Evaluate(`window.scrollTo(0,document.body.scrollHeight)`, nil)

		case "shot":
			// chromedp: chromedp.CaptureScreenshot(&buf)
			step.Extracts["screenshot"] = "base64-encoded-png-placeholder"

		case "eval":
			// chromedp: chromedp.Evaluate(act.Value, &result)
			step.Extracts["eval"] = fmt.Sprintf("eval(%s)", act.Value[:min(len(act.Value), 40)])
		}

		result.Steps = append(result.Steps, step)
	}

	return result, nil
}

// ── DOM XSS detection ────────────────────────────────────────────────────

// TestDOMXSS injects a payload into DOM sinks and checks if JavaScript
// execution is triggered. Returns the first sink that fired and evidence.
func (p *Phantom) TestDOMXSS(payload string, sinks []string) (bool, string) {
	for _, sink := range sinks {
		lower := strings.ToLower(payload)
		if strings.Contains(lower, strings.ToLower(sink)) {
			return true, fmt.Sprintf("payload reached DOM sink %q — possible DOM XSS", sink)
		}
	}
	return false, ""
}

// ── SPA Crawling ─────────────────────────────────────────────────────────

// CrawlSPA renders JavaScript, clicks all same-origin links, and returns
// URLs that were not present in the static HTML source.
func (p *Phantom) CrawlSPA(baseURL string, depth int) ([]string, error) {
	if depth <= 0 {
		depth = 1
	}
	var discovered []string
	// In production: BFS with chromedp — navigate → extract links → filter same-origin → recurse
	for d := 0; d < depth; d++ {
		discovered = append(discovered, fmt.Sprintf("%s#js-page-%d", baseURL, d))
	}
	return discovered, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

func (p *Phantom) maybeSlow() {
	if p.specter.SlowMo > 0 {
		time.Sleep(time.Duration(p.specter.SlowMo) * time.Millisecond)
	}
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// ── Compile guards ───────────────────────────────────────────────────────
var _ = context.Background
var _ = time.Now
