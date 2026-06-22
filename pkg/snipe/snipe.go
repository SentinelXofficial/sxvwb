// Package snipe runs a hyper-focused single-endpoint attack where every
// module attacks the same target simultaneously. Unlike a normal scan which
// crawls and discovers, snipe mode loads all modules and fires them all at
// one URL — maximum coverage in minimum time.
package snipe

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Focused defines a single-target module execution.
type Focused struct {
	Target    *http.Client
	URL       string
	Header    map[string]string
	Cookie    string
	Modules   []ModuleFn
	Timeout   time.Duration
	Threads   int
}

// ModuleFn is a function that takes a URL and returns findings.
type ModuleFn func(client *http.Client, url string, headers map[string]string, cookie string) []Hit

// Hit is a lightweight finding from a focused scan.
type Hit struct {
	Module   string
	Type     string
	Severity string
	Evidence string
	Latency  time.Duration
}

// Outcome holds the results of a focused attack.
type Outcome struct {
	URL        string
	StartedAt  time.Time
	Duration   time.Duration
	TotalMods  int
	RunMods    int
	Hits       []Hit
	BySeverity map[string]int
}

// ── Register known modules ───────────────────────────────────────────────

// AllModules returns the full list of focused module signatures. The caller
// MUST wire each to the real module implementations.
func AllModules() []string {
	return []string{
		"sqli", "blindsqli", "xss", "cmdi", "ssrf", "xxe", "nosqli",
		"openredirect", "pathtraversal", "ssti", "crlf", "jsoninjection",
		"headercan", "cookiescan", "hostheader", "fileupload", "jwt",
		"idor", "csrf", "cookieaudit", "proto", "deserialize",
		"cachepoison", "lfi", "smuggling", "ratelimit", "clutch",
	}
}

// ── Runner ────────────────────────────────────────────────────────────────

// Fire launches all registered modules against a single URL concurrently.
func (f *Focused) Fire() *Outcome {
	o := &Outcome{
		URL:        f.URL,
		StartedAt:  time.Now(),
		TotalMods:  len(f.Modules),
		BySeverity: make(map[string]int),
	}

	if f.Threads <= 0 {
		f.Threads = len(f.Modules)
	}
	if f.Timeout == 0 {
		f.Timeout = 30 * time.Second
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, f.Threads)

	for _, mod := range f.Modules {
		wg.Add(1)
		sem <- struct{}{}
		go func(fn ModuleFn) {
			defer wg.Done()
			defer func() { <-sem }()

			t0 := time.Now()
			hits := fn(f.Target, f.URL, f.Header, f.Cookie)
			elapsed := time.Since(t0)

			mu.Lock()
			o.RunMods++
			for _, h := range hits {
				h.Latency = elapsed
				o.Hits = append(o.Hits, h)
				o.BySeverity[h.Severity]++
			}
			mu.Unlock()
		}(mod)
	}
	wg.Wait()

	o.Duration = time.Since(o.StartedAt)
	return o
}

// ── Report ────────────────────────────────────────────────────────────────

// Summary returns a one-line report.
func (o *Outcome) Summary() string {
	total := o.TotalMods
	run := o.RunMods
	hits := len(o.Hits)
	crit := o.BySeverity["CRITICAL"]
	high := o.BySeverity["HIGH"]
	return fmt.Sprintf("%s: %d/%d mods fired in %v → %d hits (%d critical, %d high)",
		o.URL, run, total, o.Duration.Round(time.Millisecond), hits, crit, high)
}

// ── Compile guards ────────────────────────────────────────────────────────
var _ = sync.Mutex{}
var _ = time.Now
