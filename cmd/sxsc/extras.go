package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxvwb/pkg/bundle"
	"github.com/SentinelXofficial/sxvwb/pkg/core"
	"github.com/SentinelXofficial/sxvwb/pkg/courier"
	"github.com/SentinelXofficial/sxvwb/pkg/delta"
	"github.com/SentinelXofficial/sxvwb/pkg/strike"
	"github.com/SentinelXofficial/sxvwb/pkg/trail"
	"github.com/SentinelXofficial/sxvwb/pkg/breach"
	"github.com/SentinelXofficial/sxvwb/pkg/clutch"
	"github.com/SentinelXofficial/sxvwb/pkg/grpcscan"
)

func runSync(repoFlag string) {
	fmt.Printf("  [sync] Pulling blueprints from community...\n")
	if repoFlag != "" {
		fmt.Printf("  [sync] Custom source: %s\n", repoFlag)
	}
	fmt.Printf("  [sync] Done — requires published blueprint repository.\n")
}

func runDiff(diffArgs string) {
	parts := strings.Fields(diffArgs)
	if len(parts) < 2 {
		fmt.Println("[!] Usage: --diff baseline.json current.json")
		os.Exit(1)
	}
	r, err := delta.Diff(parts[0], parts[1])
	if err != nil {
		fmt.Printf("[!] Diff failed: %v\n", err)
		os.Exit(1)
	}
	r.Print()
	os.Exit(r.ExitCode())
}

func runStrikeFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[!] Cannot read %s: %v\n", path, err)
		os.Exit(1)
	}
	var wrapper struct {
		Results []struct {
			Type      string `json:"type"`
			URL       string `json:"url"`
			Severity  string `json:"severity"`
			Parameter string `json:"parameter"`
			Payload   string `json:"payload"`
			Evidence  string `json:"evidence"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		fmt.Printf("[!] Invalid JSON in %s: %v\n", path, err)
		os.Exit(1)
	}
	for _, r := range wrapper.Results {
		w := strike.Forge(r.Type, r.URL, r.Parameter, r.Payload, r.Severity, r.Evidence)
		fmt.Println(w.MarkdownReport())
	}
}

func runStrikeOne(args string) {
	parts := strings.Split(args, ",")
	if len(parts) < 4 {
		fmt.Println("[!] Usage: --strike-one TYPE,URL,PARAM,PAYLOAD[,SEVERITY,EVIDENCE]")
		os.Exit(1)
	}
	sev, ev := "MEDIUM", ""
	if len(parts) >= 5 { sev = parts[4] }
	if len(parts) >= 6 { ev = parts[5] }
	w := strike.Forge(parts[0], parts[1], parts[2], parts[3], sev, ev)
	fmt.Println(w.MarkdownReport())
}

func runInteract() {
	fmt.Println("\n--- sxsc Interactive Scan Setup ---")
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Target URL: ")
	scanner.Scan()
	target := strings.TrimSpace(scanner.Text())
	fmt.Print("Cookie (optional): ")
	scanner.Scan()
	cookie := strings.TrimSpace(scanner.Text())
	fmt.Print("Scan depth [basic/full]: ")
	scanner.Scan()
	depth := strings.TrimSpace(scanner.Text())
	fmt.Print("Output file [results.json]: ")
	scanner.Scan()
	outFile := strings.TrimSpace(scanner.Text())
	if outFile == "" { outFile = "results.json" }
	fmt.Printf("\n[interact] Configured. Run manually:\n")
	fmt.Printf("  sxsc -u %s", target)
	if cookie != "" { fmt.Printf(" --cookie %s", cookie) }
	if depth == "full" { fmt.Printf(" --crawl --all") }
	fmt.Printf(" --json-output %s\n\n", outFile)
}

func runSARIF(results []core.ScanResult, sarifVer, sarifPath string) {
	var tr []trail.ScanResult
	for _, r := range results {
		tr = append(tr, trail.ScanResult{
			Type: r.Type, URL: r.URL, Method: r.Method,
			Parameter: r.Parameter, Payload: r.Payload,
			Severity: r.Severity, Evidence: r.Evidence, Timestamp: r.Timestamp,
		})
	}
	if err := trail.SaveSARIF(tr, sarifVer, sarifPath); err != nil {
		fmt.Printf("[!] SARIF error: %v\n", err)
	} else {
		fmt.Printf("[+] SARIF report -> %s\n", sarifPath)
	}
}

func runBundle(bundlePath, bundleOut, target string) {
	data, err := os.ReadFile(bundlePath)
	if err != nil { fmt.Printf("[!] Bundle: %v\n", err); return }
	var wrapper struct {
		Results []bundle.Finding `json:"results"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		fmt.Printf("[!] Bundle: invalid JSON: %v\n", err); return
	}
	b := bundle.New(target, wrapper.Results)
	zipPath, err := b.Zip(bundleOut)
	if err != nil {
		fmt.Printf("[!] Bundle error: %v\n", err)
	} else {
		fmt.Printf("[+] Report bundle -> %s (%d findings)\n", zipPath, b.Stats.Total)
	}
}

func runWebhook(results []core.ScanResult, hookURL, hookTarget, displayTarget string, elapsed time.Duration) {
	top := make([]string, 0, 5)
	for _, r := range results {
		if len(top) >= 5 { break }
		top = append(top, fmt.Sprintf("[%s] %s", r.Severity, r.Type))
	}
	if hookTarget == "" { hookTarget = displayTarget }
	m := courier.Missive{
		Target: hookTarget, Date: time.Now(), TopFindings: top,
		Stats: courier.Stats{
			Total: len(results), Critical: countSev(results, "CRITICAL"),
			High: countSev(results, "HIGH"), Medium: countSev(results, "MEDIUM"),
			Low: countSev(results, "LOW"), Info: countSev(results, "INFO"),
			Duration: elapsed,
		},
	}
	if err := m.Deliver(hookURL); err != nil {
		fmt.Printf("[!] Webhook: %v\n", err)
	}
}

func runCIExit(results []core.ScanResult) {
	var tr []trail.ScanResult
	for _, r := range results {
		tr = append(tr, trail.ScanResult{Type: r.Type, URL: r.URL, Severity: r.Severity})
	}
	os.Exit(trail.ExitCode(tr))
}

func countSev(results []core.ScanResult, sev string) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Severity, sev) { n++ }
	}
	return n
}

func or(a, b string) string { if a != "" { return a }; return b }

func severityColor(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH": return "\033[31m"
	case "MEDIUM": return "\033[33m"
	case "LOW": return "\033[32m"
	default: return "\033[36m"
	}
}

// ── Sprint B helpers ─────────────────────────────────────────────────

func runClutch(client *http.Client, cfg *core.Config, t core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	for _, window := range clutch.Slip(client, t.URL, cfg.Cookie, cfg.Headers) {
		results = append(results, core.ScanResult{
			Type: "Race Condition / TOCTOU", URL: window.URL, Method: window.Method,
			Parameter: fmt.Sprintf("concurrent=%d", window.Concurrent), Payload: fmt.Sprintf("%d vs %d", window.Status1, window.Status2),
			Severity: "HIGH", Evidence: window.Evidence, Timestamp: time.Now(),
		})
	}
	return results
}

func runBreach(client *http.Client, cfg *core.Config, t core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	oauths := breach.OAuthProbe(client, t.URL)
	for _, o := range oauths {
		for _, f := range o.Findings {
			results = append(results, core.ScanResult{
				Type: "OAuth Misconfiguration", URL: o.Endpoint, Method: "GET",
				Parameter: o.Flow, Payload: "redirect_uri=evil.com",
				Severity: "HIGH", Evidence: f, Timestamp: time.Now(),
			})
		}
	}
	samls := breach.SAMLProbe(client, t.URL)
	for _, s := range samls {
		for _, f := range s.Findings {
			results = append(results, core.ScanResult{
				Type: "SAML Misconfiguration", URL: s.Endpoint, Method: "GET",
				Parameter: "metadata", Payload: "-",
				Severity: "MEDIUM", Evidence: f, Timestamp: time.Now(),
			})
		}
	}
	return results
}

func runGrpc(client *http.Client, cfg *core.Config, t core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	for _, r := range grpcscan.Probe(client, t.URL) {
		sev := "MEDIUM"
		if r.Reflection { sev = "HIGH" }
		results = append(results, core.ScanResult{
			Type: "gRPC Reflection Exposed", URL: r.Endpoint, Method: "POST",
			Parameter: "reflection", Payload: "-",
			Severity: sev, Evidence: r.Evidence, Timestamp: time.Now(),
		})
	}
	return results
}

// ── Domain Restrictions ─────────────────────────────────────────────────

// blockedDomains lists TLDs and domains that sxvwb is prohibited from scanning.
var blockedDomains = []string{
	".co.id",
	".go.id",
	".ac.id",
	".sch.id",
	".mil.id",
	".or.id",
	".net.id",
	".web.id",
	".my.id",
	".biz.id",
	".desa.id",
	".ponpes.id",
	".id",
	"github.com",
}

// isRestrictedDomain checks whether a hostname matches any blocked domain pattern.
func isRestrictedDomain(host string) bool {
	host = strings.ToLower(host)
	for _, blocked := range blockedDomains {
		if strings.HasSuffix(host, blocked) || host == strings.TrimPrefix(blocked, ".") {
			return true
		}
	}
	return false
}
