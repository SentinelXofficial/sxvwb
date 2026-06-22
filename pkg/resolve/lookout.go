// Package resolve probes DNS records for hostnames — A, AAAA, CNAME chains,
// MX, TXT, NS — and provides helpers for subdomain takeover detection.
package resolve

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Lookout holds the full DNS intelligence for one hostname.
type Lookout struct {
	Name    string        `json:"name"`
	Addrs   []string      `json:"addrs,omitempty"`    // A + AAAA records
	CNAME   string        `json:"cname,omitempty"`    // canonical name
	Chain   []string      `json:"chain,omitempty"`    // full CNAME resolution path
	MX      []string      `json:"mx,omitempty"`       // mail exchangers
	TXT     []string      `json:"txt,omitempty"`      // text records
	NS      []string      `json:"ns,omitempty"`       // name servers
	Latency time.Duration `json:"latency_ms"`         // lookup duration
	Error   string        `json:"error,omitempty"`    // resolution failure reason
}

// ── Resolution ───────────────────────────────────────────────────────────

// Scout resolves a single hostname across all record types.
func Scout(hostname string) *Lookout {
	t0 := time.Now()
	l := &Lookout{Name: hostname}

	addrs, err := net.LookupHost(hostname)
	l.Latency = time.Since(t0)
	if err != nil {
		l.Error = err.Error()
		return l
	}
	l.Addrs = addrs

	// CNAME chain — follow until termination or cycle
	cname, err := net.LookupCNAME(hostname)
	if err == nil {
		clean := strings.TrimSuffix(cname, ".")
		if clean != strings.TrimSuffix(hostname, ".") {
			l.CNAME = clean
			l.Chain = traceChain(clean, 10)
		}
	}

	// Optional records (non-fatal)
	if mxs, err := net.LookupMX(hostname); err == nil {
		for _, mx := range mxs {
			l.MX = append(l.MX, fmt.Sprintf("%s(%d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	}
	if txts, err := net.LookupTXT(hostname); err == nil {
		l.TXT = txts
	}
	if nss, err := net.LookupNS(hostname); err == nil {
		for _, ns := range nss {
			l.NS = append(l.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	return l
}

// ScoutMany resolves multiple hostnames concurrently with bounded workers.
func ScoutMany(hostnames []string, workers int) []*Lookout {
	if workers <= 0 {
		workers = 10
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		sem     = make(chan struct{}, workers)
		results []*Lookout
	)
	for _, h := range hostnames {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			l := Scout(host)
			mu.Lock()
			results = append(results, l)
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return results
}

// ── Analysis ─────────────────────────────────────────────────────────────

// Dangling returns true if the CNAME target no longer resolves — the core
// signal for subdomain takeover.
func (l *Lookout) Dangling() bool {
	if l.CNAME == "" {
		return false
	}
	// The CNAME target must not resolve, AND the original host's A record
	// should also fail or point to something inert.
	_, err := net.LookupHost(l.CNAME)
	return err != nil
}

// CloudService checks if the CNAME points to a known cloud/hosting provider
// whose resources can be claimed for subdomain takeover.
func (l *Lookout) CloudService() (string, bool) {
	targets := map[string]string{
		"s3.amazonaws.com":            "AWS S3 Bucket",
		"s3-website":                  "AWS S3 Website Hosting",
		"cloudfront.net":              "AWS CloudFront CDN",
		"elb.amazonaws.com":           "AWS ELB (Classic)",
		"blob.core.windows.net":       "Azure Blob Storage",
		"cloudapp.net":                "Azure Cloud Services",
		"azurewebsites.net":           "Azure App Service",
		"trafficmanager.net":          "Azure Traffic Manager",
		"herokuapp.com":               "Heroku",
		"herokudns.com":               "Heroku DNS",
		"github.io":                   "GitHub Pages",
		"fastly.net":                  "Fastly CDN",
		"netlify.app":                 "Netlify",
		"firebaseapp.com":             "Firebase Hosting",
		"myshopify.com":               "Shopify",
		"bitbucket.io":                "Bitbucket Pages",
		"surge.sh":                    "Surge.sh",
		"pantheonsite.io":             "Pantheon",
		"zendesk.com":                 "Zendesk Help Center",
		"readme.io":                   "Readme.io Docs",
		"statuspage.io":               "Atlassian Statuspage",
		"cargo.site":                  "Cargo Collective",
		"hatenablog.com":              "Hatena Blog",
		"launchrock.com":              "LaunchRock",
		"unbouncepages.com":           "Unbounce",
		"tildacdn.com":                "Tilda CDN",
		"acquia-test.co":              "Acquia Cloud",
	}
	lower := strings.ToLower(l.CNAME)
	for suffix, name := range targets {
		if strings.Contains(lower, suffix) {
			return name, true
		}
	}
	return "", false
}

// HasRecord returns true if any DNS record was found (host exists).
func (l *Lookout) HasRecord() bool {
	return len(l.Addrs) > 0 || l.CNAME != "" || len(l.MX) > 0
}

// ── Internal ─────────────────────────────────────────────────────────────

func traceChain(start string, max int) []string {
	var chain []string
	seen := make(map[string]bool)
	current := strings.TrimSuffix(start, ".")
	seen[current] = true
	for i := 0; i < max; i++ {
		cname, err := net.LookupCNAME(current)
		if err != nil {
			break
		}
		clean := strings.TrimSuffix(cname, ".")
		if clean == current || seen[clean] {
			break // reached origin or cycle
		}
		seen[clean] = true
		chain = append(chain, clean)
		current = clean
	}
	return chain
}
