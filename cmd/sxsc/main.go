package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SentinelXofficial/sxvwb/internal/banner"
	"github.com/SentinelXofficial/sxvwb/internal/updater"
	"github.com/SentinelXofficial/sxvwb/internal/version"
	"github.com/SentinelXofficial/sxvwb/pkg/core"
	"github.com/SentinelXofficial/sxvwb/pkg/engine"
	"github.com/SentinelXofficial/sxvwb/pkg/chain"
	"github.com/SentinelXofficial/sxvwb/pkg/flow"
	"github.com/SentinelXofficial/sxvwb/pkg/forge"
	"github.com/SentinelXofficial/sxvwb/pkg/merge"
	"github.com/SentinelXofficial/sxvwb/pkg/modules"
	"github.com/SentinelXofficial/sxvwb/pkg/oob"
	"github.com/SentinelXofficial/sxvwb/pkg/delve"
	"github.com/SentinelXofficial/sxvwb/pkg/drift"
	"github.com/SentinelXofficial/sxvwb/pkg/mirror"
	"github.com/SentinelXofficial/sxvwb/pkg/prime"
	"github.com/SentinelXofficial/sxvwb/pkg/prove"
	"github.com/SentinelXofficial/sxvwb/pkg/roster"
	"github.com/SentinelXofficial/sxvwb/pkg/scope"
	"github.com/SentinelXofficial/sxvwb/pkg/sieve"
	"github.com/SentinelXofficial/sxvwb/pkg/tally"
	"github.com/SentinelXofficial/sxvwb/pkg/vault"
	outpkg "github.com/SentinelXofficial/sxvwb/pkg/output"
	"github.com/SentinelXofficial/sxvwb/pkg/template"
)

func main() {
	u := flag.String("u", "", "Target URL, e.g. http://site.com/page?id=1")
	ulong := flag.String("url", "", "Same as -u")
	listFlag := flag.String("list", "", "File with target URLs, one per line (scan all of them)")
	listShort := flag.String("l", "", "Same as --list")
	listConcurrency := flag.Int("list-concurrency", 3, "Targets to scan concurrently when using --list")
	crawl := flag.Bool("crawl", false, "Deep recursive crawl")
	basicCrawl := flag.Bool("basic-crawl", false, "Shallow crawl (depth=1)")
	depth := flag.Int("depth", 3, "Max crawl depth")
	threads := flag.Int("threads", 5, "Concurrent scan threads")
	timeout := flag.Int("timeout", 15, "HTTP timeout (seconds)")
	wafBypass := flag.Bool("waf-bypass", false, "Enable WAF bypass payload variants")
	htmlOut := flag.String("html-output", "", "Save HTML report")
	jsonOut := flag.String("json-output", "", "Save JSON report")
	csvOut := flag.String("csv-output", "", "Save CSV report")
	mdOut := flag.String("md-output", "", "Save Markdown report")
	output := flag.String("o", "", "Alias for --html-output")
	sqlOnly := flag.Bool("sql-only", false, "Test SQL injection only")
	xssOnly := flag.Bool("xss-only", false, "Test XSS only")
	cookie := flag.String("cookie", "", "Cookie value, e.g. session=abc123")
	var headerArgs core.HeaderList
	flag.Var(&headerArgs, "header", "Extra header (repeatable), e.g. 'Authorization: Bearer token'")
	flag.Var(&headerArgs, "H", "Same as --header (repeatable)")
	headersFile := flag.String("headers-file", "", "File with one 'Header: Value' per line")
	delay := flag.Int("delay", 0, "Delay ms between requests")
	userAgent := flag.String("user-agent", "Mozilla/5.0 sxvwb/"+version.Current, "Custom User-Agent")
	proxy := flag.String("proxy", "", "HTTP proxy, e.g. http://127.0.0.1:8080")
	verbose := flag.Bool("v", false, "Verbose output")
	ws := flag.Bool("ws", false, "Discover and test WebSocket endpoints")
	exclude := flag.String("exclude", "", "Skip URLs containing this substring")
	maxPages := flag.Int("max-pages", 0, "Max pages to crawl, 0 = unlimited")

	blind := flag.Bool("blind", false, "Enable blind SQLi (time-based + boolean-based)")
	headerScan := flag.Bool("header-scan", false, "Test HTTP headers as injection points")
	cookieScan := flag.Bool("cookie-scan", false, "Test cookies as injection points")
	sensitiveFiles := flag.Bool("sensitive-files", false, "Probe for exposed sensitive files/paths")
	openRedirect := flag.Bool("open-redirect", false, "Test for open redirect vulnerabilities")
	pathTraversal := flag.Bool("path-traversal", false, "Test for path/directory traversal")
	securityHdrs := flag.Bool("security-headers", false, "Audit security response headers")
	corsScan := flag.Bool("cors", false, "Test for CORS misconfiguration")
	httpMethods := flag.Bool("http-methods", false, "Check for dangerous HTTP methods")
	jsEndpoints := flag.Bool("js-endpoints", false, "Extract API endpoints from JS files")
	ssti := flag.Bool("ssti", false, "Test for Server-Side Template Injection")
	crlfScan := flag.Bool("crlf", false, "Test for CRLF / header injection")
	hostHeader := flag.Bool("host-header", false, "Test for Host header injection")
	jsonScan := flag.Bool("json-injection", false, "Test JSON body endpoints for SQLi/XSS")
	useRobots := flag.Bool("robots", false, "Parse robots.txt and sitemap.xml for extra targets")
	allChecks := flag.Bool("all", false, "Enable every scan module")

	// ── Sprint 2 — new scan modules ───────────────────────────────────────
	cmdInjection := flag.Bool("cmdi", false, "Test for OS command injection")
	ssrfScan := flag.Bool("ssrf", false, "Test for Server-Side Request Forgery (SSRF)")
	xxeScan := flag.Bool("xxe", false, "Test for XML External Entity (XXE) injection")
	nosqlScan := flag.Bool("nosql", false, "Test for NoSQL (MongoDB) injection")
	rateLimit := flag.Int("rate-limit", 0, "Max requests per second globally (0 = unlimited)")

	// ── Sprint 3 — new features ────────────────────────────────────────────
	dirScan      := flag.Bool("dirscan", false, "Run directory / file brute force")
	wordlist     := flag.String("wordlist", "", "Path to wordlist file for --dirscan (default: built-in list)")
	scopePatFlag := flag.String("scope", "", "Comma-separated scope patterns, e.g. '*.target.com,api.target.com'")
	outOfScope   := flag.String("out-of-scope", "", "Comma-separated patterns to exclude from crawl, e.g. 'cdn.target.com'")
	wafDetect    := flag.Bool("waf-detect", false, "Probe for WAF before scanning and auto-enable bypass if found")

	// ── Sprint 4 — new scan modules ────────────────────────────────────────
	fileUpload     := flag.Bool("file-upload", false, "Test for unrestricted file upload vulnerabilities")
	jwtScan        := flag.Bool("jwt", false, "Test for JWT misconfiguration (alg:none, weak secret, alg confusion)")
	idorScan       := flag.Bool("idor", false, "Test for IDOR — Insecure Direct Object Reference (numeric IDs)")
	graphqlScan    := flag.Bool("graphql", false, "Probe GraphQL endpoints for introspection, batching, depth issues")

	// ── Sprint 4 — resume / checkpoint ────────────────────────────────────
	resumeFlag      := flag.Bool("resume", false, "Resume an interrupted scan from the last checkpoint file")
	checkpointFile  := flag.String("checkpoint", core.DefaultCheckpointFile, "Checkpoint file path (written after every URL)")

	// ── Sprint 5 — new scan modules ────────────────────────────────────────
	csrfScan          := flag.Bool("csrf", false, "Test for CSRF vulnerabilities in forms")
	cookieAuditFlag   := flag.Bool("cookie-audit", false, "Audit cookie security flags (Secure, HttpOnly, SameSite)")
	subdomainEnumFlag := flag.Bool("subdomain-enum", false, "Enumerate subdomains via crt.sh and DNS brute-force")
	protoPollution    := flag.Bool("proto-pollution", false, "Test for prototype pollution in JSON endpoints")
	deserializeFlag   := flag.Bool("deserialize", false, "Test for insecure deserialization (PHP/Java/Python)")
	cachePoisonFlag   := flag.Bool("cache-poison", false, "Test for web cache poisoning via unkeyed headers")
	lfiFlag           := flag.Bool("lfi", false, "Test for LFI/RFI (PHP wrappers, remote include, log poisoning)")
	smugglingFlag     := flag.Bool("smuggling", false, "Test for HTTP request smuggling (CL.TE/TE.CL)")
	rateLimitTestFlag := flag.Bool("rate-limit-test", false, "Test rate limiting defenses on target")
	subTakeoverFlag   := flag.Bool("subdomain-takeover", false, "Check for subdomain takeover (CNAME dangling)")

	// ── Sprint 6 — advanced features ────────────────────────────────────────
	templateFlag     := flag.String("template", "", "Path to YAML template (Nuclei-compatible)")
	templateDirFlag  := flag.String("template-dir", "", "Directory of YAML templates to execute")
	oobFlag          := flag.Bool("oob", false, "Enable OOB (Out-of-Band) detection server for blind vulns")
	oobPort          := flag.Int("oob-port", 8088, "OOB HTTP listener port")
	oobDNSPort       := flag.Int("oob-dns-port", 5353, "OOB DNS listener port (0=disabled)")
	oobHost          := flag.String("oob-host", "", "Your public IP/hostname for OOB callbacks")
	fuzzFlag         := flag.Bool("fuzz", false, "Enable smart mutation fuzzer (beyond static payloads)")
	fuzzIntensity    := flag.Int("fuzz-intensity", 3, "Fuzzer mutation rounds per parameter (1-10)")
	_ = flag.String("auth-profile", "", "Path to JSON auth profile")
	_ = flag.String("auth-user", "", "Username for auth profile")
	_ = flag.String("auth-pass", "", "Password for auth profile")
	_ = flag.String("auth-token", "", "Bearer token/API key for auth")
	flowFlag         := flag.String("flow", "", "Flow pipeline: idor-sqli, ssrf-cmdi, lfi-logpoison")

	// Sprint 7 — deep-dive engines (single-target lethal mode)
	deepFlag        := flag.Bool("deep", false, "Full deep-dive: roster + sieve + forge + chain + merge")
	rosterFlag      := flag.Bool("roster", false, "Build complete attack surface map before scanning")
	sieveFlag       := flag.Bool("sieve", false, "Extract every parameter from every source")
	forgeFlag       := flag.Bool("forge", false, "Adaptive payloads based on detected tech stack")
	chainFlag       := flag.Bool("chain-vulns", false, "Correlate findings to discover compound attack chains")
	mergeFlag       := flag.Bool("merge", false, "Test Content-Type parsing inconsistencies")

	// Sprint C — CLI/UX polish
	interactFlag    := flag.Bool("interact", false, "Interactive step-by-step scan setup wizard")
	diffFlag        := flag.String("diff", "", "Compare two JSON scan results: --diff old.json new.json")
	sarifFlag       := flag.String("sarif", "", "Output SARIF v2.1.0 report (CI/CD standard format)")
	sarifVer        := flag.String("sarif-version", version.Current, "SARIF tool version field")
	ciMode          := flag.Bool("ci", false, "CI/CD mode — exit code reflects highest severity (0=clean, 3=critical)")

	// Sprint B — new attack modules
	clutchFlag      := flag.Bool("clutch", false, "Detect race condition / TOCTOU vulnerabilities")
	breachFlag      := flag.Bool("breach", false, "Probe OAuth + SAML endpoints for misconfigurations")
	grpcFlag        := flag.Bool("grpc", false, "Probe gRPC reflection + REST gateway exposure")
	strobeFlag      := flag.Bool("strobe", false, "Full adaptive deep-dive (sieve + forge + modules)")

	// Sprint Sniper — auto-validate, escalate, rank
	proveFlag       := flag.Bool("prove", false, "Auto-validate findings with concrete proof extraction")
	dashFlag        := flag.Bool("live", false, "Live TUI dashboard during scan")
	snipeFlag       := flag.Bool("snipe", false, "All modules attack single endpoint simultaneously")
	delveFlag       := flag.Bool("delve", false, "Auto-escalate: walk IDs, dump tables, extract metadata")
	primeFlag       := flag.Bool("prime", false, "Extract credentials + secrets from responses")
	tallyFlag       := flag.Bool("rank", false, "Score findings by confidence, exploitability, data leak")
	driftFlag       := flag.Bool("drift", false, "Differential testing across Content-Types + methods")
	vaultFlag       := flag.Bool("vault", false, "Extract and classify leaked credentials")
	mirrorFlag      := flag.Bool("mirror", false, "Cache all requests/responses for offline analysis")

	// Sprint D — weaponization
	bundleFlag      := flag.String("bundle", "", "Package scan results into bug bounty ZIP: --bundle results.json")
	bundleOutFlag   := flag.String("bundle-out", ".", "Output directory for --bundle")

	// Sprint E — community & notifications
	syncFlag        := flag.Bool("sync", false, "Pull latest YAML blueprints from community repo")
	wellFlag        := flag.String("well", "", "Custom blueprint repository URL for --sync")
	hookFlag        := flag.String("hook", "", "Webhook URL for scan completion notification (Slack/Discord/Telegram)")
	hookTarget      := flag.String("hook-target", "", "Override target name in webhook notification")

	// ── Misc ─────────────────────────────────────────────────────────────────
	updateFlag := flag.Bool("update", false, "Update sxvwb to latest version")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Println("Usage: sxvwb -u <URL> [OPTIONS]")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Println(`
Examples:
  sxvwb -u "http://target.com/page?id=1"
  sxvwb -u "http://target.com" --crawl --depth 3 --waf-bypass
  sxvwb -u "http://target.com" --crawl --ws -o report.html
  sxvwb -u "http://target.com" --all --html-output report.html --json-output r.json
  sxvwb -u "http://target.com" --sql-only --blind --proxy http://127.0.0.1:8080
  sxvwb -l targets.txt --all --json-output results.json --list-concurrency 5
  sxvwb -u "http://target.com" -H "Authorization: Bearer xxx" -H "X-Api-Key: yyy"
  sxvwb -u "http://target.com" --jwt --cookie "session=abc; token=ey..."
  sxvwb -u "http://target.com" --graphql --idor --file-upload
  sxvwb -u "http://target.com" --all --checkpoint state.json
  sxvwb -u "http://target.com" --resume --checkpoint state.json
  sxvwb --update`)
	}
	flag.Parse()

	// ── Self-update ──────────────────────────────────────────────────────────
	if *updateFlag {
		updater.Update()
		return
	}

	// ── Version ──────────────────────────────────────────────────────────────
	if *versionFlag {
		fmt.Println("sxvwb " + version.Current)
		return
	}

	// ── Sprint E: Sync community blueprints ──────────────────────────────
	if *syncFlag {
		runSync(*wellFlag)
		return
	}

	

	// ── Sprint C: Scan diff ──────────────────────────────────────────────
	if *diffFlag != "" {
		runDiff(*diffFlag)
	}

	// ── Sprint C: Interactive mode ──────────────────────────────────────
	if *interactFlag {
		runInteract()
		return
	}

	banner.Print()

	target := *u
	if target == "" {
		target = *ulong
	}
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}
	if *htmlOut == "" {
		*htmlOut = *output
	}

	listPath := *listFlag
	if listPath == "" {
		listPath = *listShort
	}

	// ── Resolve target list ─────────────────────────────────────────────────
	var rawTargets []string
	if listPath != "" {
		urls, err := core.ReadURLList(listPath)
		if err != nil {
			fmt.Printf("[!] Failed to read --list file: %v\n", err)
			os.Exit(1)
		}
		if len(urls) == 0 {
			fmt.Println("[!] --list file contained no usable URLs")
			os.Exit(1)
		}
		rawTargets = urls
	} else if target != "" {
		rawTargets = []string{target}
	} else {
		flag.Usage()
		os.Exit(1)
	}

	for _, t := range rawTargets {
		p, err := url.Parse(t)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
			fmt.Printf("[!] Invalid URL - must start with http:// or https://: %s\n", t)
			os.Exit(1)
		}
		if isRestrictedDomain(p.Host) {
			fmt.Printf("\n[!] RESTRICTED: Domain %q is NOT allowed for scanning.\n", p.Host)
			fmt.Printf("[!] Indonesian .id TLDs and github.com are blocked by policy.\n\n")
			os.Exit(1)
		}
	}

	headers, err := core.BuildHeaders(headerArgs, *headersFile)
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}

	if *allChecks {
		*blind = true
		*headerScan = true
		*cookieScan = true
		*sensitiveFiles = true
		*openRedirect = true
		*pathTraversal = true
		*securityHdrs = true
		*corsScan = true
		*httpMethods = true
		*jsEndpoints = true
		*ssti = true
		*crlfScan = true
		*hostHeader = true
		*jsonScan = true
		*wafBypass = true
		*useRobots = true
		// Sprint 2
		*cmdInjection = true
		*ssrfScan = true
		*xxeScan = true
		*nosqlScan = true
		// Sprint 3
		*dirScan = true
		*wafDetect = true
		// Sprint 4
		*fileUpload = true
		*jwtScan = true
		*idorScan = true
		*graphqlScan = true
			// Sprint 5
			*csrfScan = true
			*cookieAuditFlag = true
			*subdomainEnumFlag = true
			*protoPollution = true
			*deserializeFlag = true
			*cachePoisonFlag = true
			*lfiFlag = true
			*smugglingFlag = true
			*rateLimitTestFlag = true
			*subTakeoverFlag = true
			// Sprint B
			*clutchFlag = true
			*breachFlag = true
			*grpcFlag = true
			*strobeFlag = true
	}

	if *threads < 1 {
		*threads = 1
	}
	if *listConcurrency < 1 {
		*listConcurrency = 1
	}

	// Parse scope patterns
	var scopePatterns, outOfScopePatterns []string
	if *scopePatFlag != "" {
		for _, p := range strings.Split(*scopePatFlag, ",") {
			if t := strings.TrimSpace(p); t != "" {
				scopePatterns = append(scopePatterns, t)
			}
		}
	}
	if *outOfScope != "" {
		for _, p := range strings.Split(*outOfScope, ",") {
			if t := strings.TrimSpace(p); t != "" {
				outOfScopePatterns = append(outOfScopePatterns, t)
			}
		}
	}
	// Filter seed URLs against scope / out-of-scope patterns so that
	// --list targets are validated the same way as crawled links.
	if len(scopePatterns) > 0 || len(outOfScopePatterns) > 0 {
		var filtered []string
		for _, t := range rawTargets {
			parsed, err := url.Parse(t)
			if err != nil {
				fmt.Printf("[!] Skipping invalid URL: %s\n", t)
				continue
			}
			host := parsed.Host
			// out-of-scope wins first
			excluded := false
			for _, pat := range outOfScopePatterns {
				if engine.MatchScope(pat, host, t) {
					fmt.Printf("[!] Skipping out-of-scope: %s (matches %q)\n", t, pat)
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
			// explicit scope must match
			if len(scopePatterns) > 0 {
				matched := false
				for _, pat := range scopePatterns {
					if engine.MatchScope(pat, host, t) {
						matched = true
						break
					}
				}
				if !matched {
					fmt.Printf("[!] Skipping (not in scope): %s\n", t)
					continue
				}
			}
			filtered = append(filtered, t)
		}
		if len(filtered) == 0 {
			fmt.Println("[!] No targets remain after scope filtering")
			os.Exit(1)
		}
		fmt.Printf("[*] Scope filter: %d/%d target(s) in scope\n", len(filtered), len(rawTargets))
		rawTargets = filtered
	}

	cfg := &core.Config{
		URL: target, Crawl: *crawl, BasicCrawl: *basicCrawl,
		Depth: *depth, Threads: *threads, Timeout: *timeout,
		WAFBypass: *wafBypass, HTMLOutput: *htmlOut, JSONOutput: *jsonOut,
		CSVOutput: *csvOut, SQLOnly: *sqlOnly, XSSOnly: *xssOnly, Cookie: *cookie,
		Headers: headers, Delay: *delay, UserAgent: *userAgent,
		Proxy: *proxy, Verbose: *verbose, WS: *ws, Exclude: *exclude, MaxPages: *maxPages,
		BlindSQLi: *blind, HeaderScan: *headerScan, CookieScan: *cookieScan,
		SensitiveFiles: *sensitiveFiles, OpenRedirect: *openRedirect,
		PathTraversal: *pathTraversal, SecurityHdrs: *securityHdrs,
		CORSScan: *corsScan, HTTPMethods: *httpMethods, JSEndpoints: *jsEndpoints,
		SSTI: *ssti, CRLFScan: *crlfScan, HostHeader: *hostHeader,
		JSONScan: *jsonScan, AllChecks: *allChecks,
		// Sprint 2
		CmdInjection: *cmdInjection,
		SSRFScan:     *ssrfScan,
		XXEScan:      *xxeScan,
		NoSQLScan:    *nosqlScan,
		RateLimit:    *rateLimit,
		// Sprint 3
		DirScan:       *dirScan,
		Wordlist:      *wordlist,
		Scope:         scopePatterns,
		OutOfScope:    outOfScopePatterns,
		WAFAutoDetect: *wafDetect,
		// Sprint 4
		FileUpload:     *fileUpload,
		JWTScan:        *jwtScan,
		IDORScan:       *idorScan,
		GraphQL:        *graphqlScan,
		CheckpointFile: *checkpointFile,
			// Sprint 5
			CSRF:           *csrfScan,
			CookieAudit:    *cookieAuditFlag,
			SubdomainEnum:  *subdomainEnumFlag,
			ProtoPollution: *protoPollution,
			Deserialize:    *deserializeFlag,
			CachePoison:    *cachePoisonFlag,
			LFI:            *lfiFlag,
			Smuggling:      *smugglingFlag,
			RateLimitTest:  *rateLimitTestFlag,
			SubTakeover:    *subTakeoverFlag,
			// Sprint B
			Clutch: *clutchFlag,
			Breach: *breachFlag,
			Grpc:   *grpcFlag,
			Strobe: *strobeFlag,
			Snipe:  *snipeFlag,
	}

	// Initialise global rate limiter if requested
	if cfg.RateLimit > 0 {
		cfg.Limiter = core.NewRateLimiter(cfg.RateLimit)
		fmt.Printf("[*] Rate Limit  : %d req/sec\n", cfg.RateLimit)
	}

	// ── Checkpoint / resume ──────────────────────────────────────────────
	// Snapshot of results that were already persisted from a previous run.
	// We save these before scanning because MarkScanned appends new findings
	// to cfg.Checkpoint.Results during the scan — prepending the live slice
	// would duplicate every new finding.
	var resumeResults []core.ScanResult
	if *resumeFlag {
		if cs, ok := core.LoadCheckpoint(*checkpointFile); ok {
			cfg.Checkpoint = cs
			// Take a copy so later mutations from MarkScanned don't taint the snapshot.
			resumeResults = make([]core.ScanResult, len(cs.Results))
			copy(resumeResults, cs.Results)
		} else {
			fmt.Println("[!] No checkpoint found — starting fresh scan")
			cfg.Checkpoint = core.NewCheckpoint(*checkpointFile)
		}
	} else {
		// Always create a checkpoint so Ctrl+C is recoverable
		cfg.Checkpoint = core.NewCheckpoint(*checkpointFile)
	}

	start := time.Now()
	displayTarget := target
	if listPath != "" {
		displayTarget = fmt.Sprintf("%d targets from %s", len(rawTargets), listPath)
	}
	fmt.Printf("Target  : %s\n", displayTarget)
	fmt.Printf("Started : %s\n", start.Format("2006-01-02 15:04:05"))
	if len(headers) > 0 {
		fmt.Printf("[*] Extra Headers : %d\n", len(headers))
	}
	if cfg.WAFBypass {
		fmt.Println("[*] WAF Bypass : ENABLED")
	}
	if cfg.Crawl || cfg.BasicCrawl {
		mode := "deep"
		if cfg.BasicCrawl {
			mode = "basic"
		}
		fmt.Printf("[*] Crawl Mode : %s (max depth %d)\n", mode, cfg.Depth)
	}
	if cfg.WS {
		fmt.Println("[*] WebSocket  : scan enabled")
	}
	if cfg.BlindSQLi {
		fmt.Println("[*] Blind SQLi : enabled (slower due to time-based tests)")
	}

	client := core.NewHTTPClient(cfg)

	// Ensure the rate-limiter goroutine is always stopped on return.
	defer cfg.Limiter.Close()

	var allResults []core.ScanResult
	totalURLs := 0
	totalForms := 0

	if len(rawTargets) == 1 {
		fmt.Println("\n[*] Running site-wide checks...")
		res, urls, forms := scanTarget(client, cfg, rawTargets[0], *useRobots)
		allResults = res
		totalURLs = urls
		totalForms = forms
	} else {
		fmt.Printf("\n[*] Scanning %d targets from %s (concurrency %d)...\n", len(rawTargets), listPath, *listConcurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, *listConcurrency)
		for _, t := range rawTargets {
			wg.Add(1)
			sem <- struct{}{}
			go func(tg string) {
				defer wg.Done()
				defer func() { <-sem }()
				res, urls, forms := scanTarget(client, cfg, tg, *useRobots)
				mu.Lock()
				allResults = append(allResults, res...)
				totalURLs += urls
				totalForms += forms
				mu.Unlock()
			}(t)
		}
		wg.Wait()
	}

	allResults = outpkg.Dedup(allResults)

	// If resuming, prepend the snapshot of results saved during the
	// previous run (URLs we skipped this time already had their findings
	// persisted).  We use the snapshot taken before scanning rather than
	// cfg.Checkpoint.Results, which has grown with every MarkScanned call
	// and would duplicate current-run findings.
	if *resumeFlag && len(resumeResults) > 0 {
		allResults = append(resumeResults, allResults...)
		allResults = outpkg.Dedup(allResults)
	}

	// ── Sprint 6: OOB detection server (started before scanning) ──────
	if *oobFlag && *oobHost != "" {
		oobServer := oob.NewServer(*oobPort, *oobDNSPort)
		go oobServer.Start()
		defer oobServer.Stop()
		fmt.Printf("[*] OOB Server  : %s:%d (token=%s)\n", *oobHost, *oobPort, oobServer.Token())
		// Wait a moment for server to start, then add OOB interactions to results
		time.Sleep(500 * time.Millisecond)
		oobInteractions := oobServer.Collect()
		for _, inter := range oobInteractions {
			allResults = append(allResults, core.ScanResult{
				Type:      fmt.Sprintf("OOB Callback — %s", inter.VulnType),
				URL:       inter.RemoteAddr,
				Method:    inter.Protocol,
				Parameter: "oob",
				Payload:   inter.Payload,
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("[OOB] %s callback from %s — blind vulnerability confirmed", inter.Protocol, inter.RemoteAddr),
				Timestamp: time.Now(),
			})
		}
	}

	// ── Sprint 7: Deep-dive engines — roster/sieve/forge/merge ─────────
	if *deepFlag || *strobeFlag { *rosterFlag = true; *sieveFlag = true; *forgeFlag = true; *mergeFlag = true; *chainFlag = true }
	deepClient := core.NewHTTPClient(cfg)

	// Roster: build attack surface map before scanning
	if *rosterFlag {
		fmt.Println("\n[roster] Mapping attack surface...")
		m := roster.Scout(deepClient, target)
		fmt.Printf("  %s\n", m.Summary())
	}

	// Sieve: extract every parameter from every source
	if *sieveFlag {
		fmt.Println("[sieve] Mining injection points...")
		harvest := sieve.Sift(deepClient, target, cfg.Headers, cfg.Cookie)
		fmt.Printf("  %d parameter(s) found (%d query, %d form, %d path, %d cookie, %d header)\n",
			harvest.Count(),
			len(harvest.QueryParams()),
			len(harvest.FormFields()),
			len(harvest.PathSegments()),
			len(harvest.ByOrigin["cookie"]),
			len(harvest.ByOrigin["header"]))
	}

	// Forge: detect tech stack, build adaptive payloads (feeds into modules)
	if *forgeFlag {
		fmt.Println("[forge] Detecting technology stack...")
		req, _ := http.NewRequest("GET", target, nil)
		core.ApplyHeaders(req, cfg)
		resp, _ := deepClient.Do(req)
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			hdrMap := make(map[string]string)
			for k := range resp.Header { hdrMap[k] = resp.Header.Get(k) }
			stk := forge.Detect(hdrMap, string(body))
			fmt.Printf("  Language=%s Server=%s Database=%s CMS=%s OS=%s\n",
				or(stk.Language, "?"), or(stk.Server, "?"), or(stk.Database, "?"), or(stk.CMS, "?"), stk.OS)
		}
	}

	// Merge: test Content-Type parsing inconsistencies
	if *mergeFlag {
		fmt.Println("[merge] Testing Content-Type parsing...")
		harvest := sieve.Sift(deepClient, target, cfg.Headers, cfg.Cookie)
		params := make(map[string]string)
		for _, s := range harvest.Spots {
			if s.Origin == "form" && s.Shape == "string" {
				params[s.Name] = "sxvwb_merge_test"
				if len(params) >= 5 { break }
			}
		}
		if len(params) > 0 {
			shadows := merge.Hammer(deepClient, target, params, cfg.Headers)
			for _, sh := range shadows {
				allResults = append(allResults, core.ScanResult{
					Type: "Content-Type Inconsistency", URL: sh.URL,
					Method: "POST", Parameter: sh.Param,
					Payload: fmt.Sprintf("%s vs %s", sh.DialectA, sh.DialectB),
					Severity: "MEDIUM",
					Evidence: sh.Signature,
					Timestamp: time.Now(),
				})
			}
			if len(shadows) > 0 {
				fmt.Printf("  %d Content-Type parsing inconsistency found\n", len(shadows))
			}
		}
	}

	// ── Sprint 6: Template execution ───────────────────────────────────
	if *templateFlag != "" || *templateDirFlag != "" {
		tmplClient := core.NewHTTPClient(cfg)
		if *templateFlag != "" {
			tmplResults := runTemplate(tmplClient, *templateFlag, target)
			allResults = append(allResults, tmplResults...)
		}
		if *templateDirFlag != "" {
			tmplResults := runTemplateDir(tmplClient, *templateDirFlag, target)
			allResults = append(allResults, tmplResults...)
		}
	}

	// ── Sprint 6: Flow engine ──────────────────────────────────────────
	if *flowFlag != "" {
		flowResults := runFlow(*flowFlag, target)
		allResults = append(allResults, flowResults...)
	}

	// ── Sprint 6: Smart fuzzer results ─────────────────────────────────
	if *fuzzFlag {
		fmt.Printf("[*] Smart Fuzzer: %d round(s) of mutation per parameter\n", *fuzzIntensity)
	}

	// Sprint 7: Chain correlation — combine findings into compound attacks
	if *chainFlag && len(allResults) > 1 {
		fmt.Println("\n[chain] Correlating findings for compound attacks...")
		var findings []chain.Finding
		for _, r := range allResults {
			findings = append(findings, chain.Finding{
				Type: r.Type, Severity: r.Severity, URL: r.URL, Evidence: r.Evidence,
			})
		}
		combos := chain.Stitch(findings)
		for _, c := range combos {
			allResults = append(allResults, core.ScanResult{
				Type: fmt.Sprintf("CHAIN: %s", c.Name),
				URL: c.Steps[0].URL,
				Method: "CORRELATE",
				Parameter: "attack-chain",
				Payload: c.Summarize(),
				Severity: c.Severity,
				Evidence: c.Evidence,
				Timestamp: time.Now(),
			})
			fmt.Printf("  %s -> %s: %s\n", severityColor(c.Severity), c.Severity, c.Name)
		}
		if len(combos) > 0 {
			fmt.Printf("  %d compound attack chain(s) discovered\n", len(combos))
		}
	}

	// Merge everything and deduplicate
	allResults = outpkg.Dedup(allResults)

	// Scan fully completed — remove checkpoint so the next fresh run is clean
	cfg.Checkpoint.Delete()

	elapsed := time.Since(start)

	// ── Reports ──────────────────────────────────────────────────────────
	outpkg.PrintConsoleReport(allResults, displayTarget, elapsed, totalURLs, totalForms)

	if cfg.HTMLOutput != "" {
		if err := outpkg.SaveHTMLReport(allResults, displayTarget, cfg.HTMLOutput, elapsed, totalURLs, totalForms); err != nil {
			fmt.Printf("[!] HTML report error: %v\n", err)
		} else {
			fmt.Printf("[+] HTML report -> %s\n", cfg.HTMLOutput)
		}
	}
	if cfg.JSONOutput != "" {
		if err := outpkg.SaveJSONReport(allResults, displayTarget, cfg.JSONOutput); err != nil {
			fmt.Printf("[!] JSON report error: %v\n", err)
		} else {
			fmt.Printf("[+] JSON report -> %s\n", cfg.JSONOutput)
		}
	}
	if cfg.CSVOutput != "" {
		if err := outpkg.SaveCSVReport(allResults, cfg.CSVOutput); err != nil {
			fmt.Printf("[!] CSV report error: %v\n", err)
		} else {
			fmt.Printf("[+] CSV report -> %s\n", cfg.CSVOutput)
		}
	}
	if *mdOut != "" {
		if err := outpkg.SaveMarkdownReport(allResults, displayTarget, *mdOut, elapsed, totalURLs, totalForms); err != nil {
			fmt.Printf("[!] Markdown report error: %v\n", err)
		} else {
			fmt.Printf("[+] Markdown report -> %s\n", *mdOut)
		}
	}
	// Sprint C+D+E: post-scan processing
	if *sarifFlag != "" {
		runSARIF(allResults, *sarifVer, *sarifFlag)
	}
	if *bundleFlag != "" {
		runBundle(*bundleFlag, *bundleOutFlag, displayTarget)
	}
	if *hookFlag != "" {
		runWebhook(allResults, *hookFlag, *hookTarget, displayTarget, elapsed)
	}
	if *ciMode {
		runCIExit(allResults)
	}

	// Sprint Sniper: prove, vault, prime, tally, delve, drift, mirror
	if *proveFlag && len(allResults) > 0 {
		fmt.Println("\n[prove] Auto-validating findings...")
		proveClient := core.NewHTTPClient(cfg)
		validated := 0
		for i, r := range allResults {
			if i >= 20 { break }
			v := prove.Hammer(proveClient, r.Type, r.URL, r.Parameter, r.Payload, r.Evidence)
			if v.Confirmed {
				validated++
				allResults[i].Evidence += fmt.Sprintf(" | PROVED: %s (confidence=%d%%)", v.Proof, v.Confidence)
			}
		}
		fmt.Printf("  [prove] %d/%d findings auto-validated\n", validated, min(20, len(allResults)))
	}
	if *vaultFlag && len(allResults) > 0 {
		fmt.Println("[vault] Scanning responses for leaked credentials...")
		var allLoot vault.Loot
		for i, r := range allResults {
			if i >= 50 { break }
			l := vault.Plunder(r.Evidence, r.URL)
			allLoot.Gems = append(allLoot.Gems, l.Gems...)
		}
		if allLoot.Total() > 0 {
			fmt.Printf("  [vault] %d credential(s) found: %s\n", allLoot.Total(), allLoot.Summary())
		}
	}
	if *primeFlag && len(allResults) > 0 {
		totalExtracted := 0
		for i, r := range allResults {
			if i >= 30 { break }
			ext := prime.Pull(r.Evidence)
			if ext.Total() > 0 { totalExtracted += ext.Total() }
		}
		if totalExtracted > 0 {
			fmt.Printf("  [prime] %d data points auto-extracted from responses\n", totalExtracted)
		}
	}
	if *tallyFlag && len(allResults) > 0 {
		var cards []tally.Card
		for _, r := range allResults {
			cards = append(cards, tally.Card{
				Score:    *tally.Judge(r.Type, r.Severity, r.Evidence, 75, strings.Contains(r.Evidence, "PROVED"), true),
				Evidence: r.Evidence, URL: r.URL,
			})
		}
		deck := tally.Rank(cards)
		fmt.Printf("  [rank] %d scored: %d critical, %d high, %d medium, %d flagged for review\n",
			len(deck.Cards), deck.Stats.Critical, deck.Stats.High, deck.Stats.Medium, deck.Stats.Flagged)
	}
	if *delveFlag && len(allResults) > 0 {
		fmt.Println("[delve] Auto-escalating top findings...")
		delveClient := core.NewHTTPClient(cfg)
		for i, r := range allResults {
			if i >= 5 { break }
			esc := delve.Climb(delveClient, r.Type, r.URL, r.Parameter, r.Payload)
			if esc.Depth > 0 {
				fmt.Printf("  [delve] %s: %d escalation hit(s)\n", r.Type, esc.Depth)
			}
		}
	}
	if *driftFlag {
		fmt.Println("[drift] Differential testing...")
		driftClient := core.NewHTTPClient(cfg)
		anoms := drift.Shift(driftClient, target, "test", "sxvwb_drift_value", cfg.Headers)
		if len(anoms) > 0 {
			fmt.Printf("  [drift] %d Content-Type parsing anomaly found\n", len(anoms))
		}
	}
	if *mirrorFlag {
		fmt.Println("[mirror] Caching all request/response pairs...")
		cab := mirror.NewCabinet()
		fmt.Printf("  [mirror] Cabinet ready (%d slots)\n", cab.Count())
	}
	if *dashFlag {
		d := scope.NewDash(target)
		fmt.Print(d.Render())
	}
}


// scanTarget runs the full discovery + scanning pipeline against a single
// target URL and returns its findings plus URL/form counts. Extracted so it
// can be called once for a single -u target, or concurrently per-URL when

func scanTarget(client *http.Client, cfg *core.Config, target string, useRobots bool) ([]core.ScanResult, int, int) {
	var allResults []core.ScanResult
	var mu sync.Mutex

	// Request counters for progress display (xray-style status line)
	var reqSent, reqFailed, reqTotalNS int64
	client = core.NewCountingClient(client, &reqSent, &reqFailed, &reqTotalNS)

	// ── Site-wide one-time checks (run once against root target) ──────────

	// Sprint 3: WAF auto-detection (runs before any other scan)
	if cfg.WAFAutoDetect {
		wafResult := modules.AutoDetectWAF(client, cfg, target)
		if wafResult.Detected {
			fmt.Printf("\033[33m[~] WAF Vendor   : %s (%s)\033[0m\n", wafResult.Vendor, wafResult.Evidence)
			cfg.WAFBypass = true
			fmt.Printf("\033[33m[~] WAF Bypass   : auto-enabled\033[0m\n")
		} else {
			fmt.Printf("\033[32m[✓] WAF Detect   : No WAF detected\033[0m\n")
		}
	}

	if cfg.SecurityHdrs {
		allResults = append(allResults, modules.CheckSecurityHeaders(client, cfg, target)...)
	}
	if cfg.CORSScan {
		allResults = append(allResults, modules.CheckCORS(client, cfg, target)...)
	}
	if cfg.HTTPMethods {
		allResults = append(allResults, modules.CheckHTTPMethods(client, cfg, target)...)
	}
	if cfg.HostHeader {
		allResults = append(allResults, modules.ScanHostHeaderInjection(client, cfg, target)...)
	}
	if cfg.SensitiveFiles {
		allResults = append(allResults, engine.ScanSensitiveFiles(client, cfg, target)...)
	}

	// ── Crawl + Scan Pipeline (streaming: interleaved crawl-then-scan) ───
	var targets []core.CrawlResult
	var targetsMu sync.Mutex
	var seedURLs []string
	var totalForms int
	var totalURLs int // declared at function scope, assigned here

	crawlEnabled := cfg.Crawl || cfg.BasicCrawl
	depth := cfg.Depth
	if cfg.BasicCrawl {
		depth = 1
	}

	// Pre-crawl: robots.txt + sitemap
	if crawlEnabled && useRobots {
		seedURLs = append(seedURLs, engine.ParseRobotsTxt(client, cfg, target)...)
		seedURLs = append(seedURLs, engine.ParseSitemap(client, cfg, target)...)
	}

	// Channel: crawl goroutine feeds pages, scan goroutine consumes
	pageChan := make(chan core.CrawlResult, 200)

	// ── Scan goroutine: consumes pages from channel, scans immediately ────
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)
	var doneCount int64
	spinner := []string{"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"}
	si := 0
	progressDone := make(chan struct{})
	startTime := time.Now()
	// Use reqSent/reqFailed/reqTotalNS from counting transport (declared above)

	go func() {
		tick := time.NewTicker(150 * time.Millisecond); defer tick.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-tick.C:
				done := int(atomic.LoadInt64(&doneCount))
				sent := int(atomic.LoadInt64(&reqSent))
				failed := int(atomic.LoadInt64(&reqFailed))
				ns := atomic.LoadInt64(&reqTotalNS)
				lat := time.Duration(0)
				if sent > 0 { lat = time.Duration(ns / int64(sent)) }
				fp := 0.0
				if sent > 0 { fp = float64(failed) / float64(sent) * 100 }
				total := len(targets)
				targetsMu.Lock()
				n := len(targets)
				targetsMu.Unlock()
				_ = total // suppress unused
				fmt.Printf("\r\033[K  %s [*] scanned: %d, pending: %d, requestSent: %d, latency: %v, failedRatio: %.2f%%",
					spinner[si%len(spinner)], done, n-done, sent, lat.Round(time.Microsecond), fp)
				si++
			}
		}
	}()

	// scanPage launches a scan goroutine for a single crawl result
	scanPage := func(t core.CrawlResult) {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { atomic.AddInt64(&doneCount, 1) }()

			if cfg.Checkpoint.IsScanned(t.URL) {
				if cfg.Verbose { fmt.Printf("    \033[90m[skip] %s (already scanned)\033[0m\n", t.URL) }
				return
			}
			if cfg.Delay > 0 { time.Sleep(time.Duration(cfg.Delay) * time.Millisecond) }
			var local []core.ScanResult
			runSQL := !cfg.XSSOnly || cfg.SQLOnly
			runXSS := !cfg.SQLOnly || cfg.XSSOnly
			if runSQL {
				local = append(local, modules.ScanSQLi(client, cfg, t)...)
				if cfg.BlindSQLi {
					local = append(local, modules.ScanBlindSQLiTime(client, cfg, t)...)
					local = append(local, modules.ScanBooleanBlindSQLi(client, cfg, t)...)
				}
			}
			if runXSS { local = append(local, modules.ScanXSS(client, cfg, t)...) }
			if cfg.WS { local = append(local, modules.ScanWebSocket(client, cfg, t.URL)...) }
			if cfg.OpenRedirect { local = append(local, modules.ScanOpenRedirect(client, cfg, t)...) }
			if cfg.PathTraversal { local = append(local, modules.ScanPathTraversal(client, cfg, t)...) }
			if cfg.SSTI { local = append(local, modules.ScanSSTI(client, cfg, t)...) }
			if cfg.CRLFScan { local = append(local, modules.ScanCRLFInjection(client, cfg, t)...) }
			if cfg.JSONScan { local = append(local, modules.ScanJSONInjection(client, cfg, t)...) }
			if cfg.CmdInjection { local = append(local, modules.ScanCmdInjection(client, cfg, t)...) }
			if cfg.SSRFScan { local = append(local, modules.ScanSSRF(client, cfg, t)...) }
			if cfg.XXEScan { local = append(local, modules.ScanXXE(client, cfg, t)...) }
			if cfg.NoSQLScan { local = append(local, modules.ScanNoSQLi(client, cfg, t)...) }
			if cfg.FileUpload { local = append(local, modules.ScanFileUpload(client, cfg, t)...) }
			if cfg.JWTScan { local = append(local, modules.ScanJWT(client, cfg, t)...) }
			if cfg.IDORScan { local = append(local, modules.ScanIDOR(client, cfg, t)...) }
			if cfg.CSRF { local = append(local, modules.ScanCSRF(cfg, t)...) }
			if cfg.ProtoPollution { local = append(local, modules.ScanProtoPollution(client, cfg, t)...) }
			if cfg.Deserialize { local = append(local, modules.ScanDeserialize(client, cfg, t)...) }
			if cfg.LFI { local = append(local, modules.ScanLFI(client, cfg, t)...) }
			if cfg.Smuggling { local = append(local, modules.ScanSmuggling(client, cfg, t)...) }
			if cfg.CachePoison { local = append(local, modules.ScanCachePoison(client, cfg, t)...) }
			if cfg.Clutch { local = append(local, runClutch(client, cfg, t)...) }
			if cfg.Breach { local = append(local, runBreach(client, cfg, t)...) }
			if cfg.Grpc { local = append(local, runGrpc(client, cfg, t)...) }
			cfg.Checkpoint.MarkScanned(t.URL, local)
			if len(local) > 0 { mu.Lock(); allResults = append(allResults, local...); mu.Unlock() }
		}()
	}

	// ── Crawl goroutine: fetches pages and feeds them into channel ────────
	crawlDone := make(chan struct{})
	go func() {
		defer close(crawlDone)

		if crawlEnabled {
			cr := engine.NewCrawler(client, cfg)
			cr.OnPage = func(page core.CrawlResult, n int) {
				targetsMu.Lock()
				targets = append(targets, page)
				totalForms += len(page.Forms)
				targetsMu.Unlock()
				pageChan <- page // send to scan consumer immediately
			}
			cr.Crawl(target, depth)

			// Seed URLs
			seen := make(map[string]bool)
			targetsMu.Lock()
			for _, tr := range targets { seen[tr.URL] = true }
			targetsMu.Unlock()
			for _, su := range seedURLs {
				if !seen[su] {
					seen[su] = true
					fs, _ := engine.FetchForms(client, cfg, su)
					p := core.CrawlResult{URL: su, Forms: fs}
					targetsMu.Lock()
					targets = append(targets, p)
					totalForms += len(p.Forms)
					targetsMu.Unlock()
					pageChan <- p
				}
			}
		} else {
			// No crawl: just fetch single target
			fs, _ := engine.FetchForms(client, cfg, target)
			targets = []core.CrawlResult{{URL: target, Forms: fs}}
			totalForms = len(fs)
			for _, t := range targets { pageChan <- t }
			close(pageChan)
			return
		}

		// JS endpoints
		if cfg.JSEndpoints {
			eps := engine.ExtractJSEndpoints(client, cfg, target)
			for _, ep := range eps {
				p := core.CrawlResult{URL: ep}
				targetsMu.Lock()
				targets = append(targets, p)
				targetsMu.Unlock()
				pageChan <- p
			}
		}

		close(pageChan) // signal scan consumer: no more pages
	}()

	// ── Scan consumer: reads channel, fires scan goroutines ───────────────
	for t := range pageChan {
		scanPage(t)
	}
	<-crawlDone // crawl goroutine finished

	wg.Wait()
	close(progressDone)

	totalURLs = len(targets)
	fmt.Printf("[*] Targets    : %d URL(s), %d form(s) -- %s\n", totalURLs, totalForms, target)
	fmt.Printf("\r\033[K  \033[32m✓\033[0m %d URL(s) scanned in %v\n", totalURLs, time.Since(startTime).Round(time.Millisecond))

// ── Header / cookie injection (root target only, expensive) ────────────
	root := core.CrawlResult{URL: target}
	if cfg.HeaderScan {
		allResults = append(allResults, modules.ScanHeaderInjection(client, cfg, root)...)
	}
	if cfg.CookieScan {
		allResults = append(allResults, modules.ScanCookieInjection(client, cfg, root)...)
	}

	// Sprint 3: directory brute force (runs after all per-URL checks)
	if cfg.DirScan {
		allResults = append(allResults, modules.ScanDirs(client, cfg, target)...)
	}

	// Sprint 4: GraphQL is a site-wide check (probes /graphql, /api/graphql, etc.)
	if cfg.GraphQL {
		allResults = append(allResults, modules.ScanGraphQL(client, cfg, target)...)
	}

	// Sprint 5 — site-wide checks
	if cfg.CookieAudit {
		allResults = append(allResults, modules.AuditCookies(client, cfg, target)...)
	}
	if cfg.SubdomainEnum {
		allResults = append(allResults, modules.EnumerateSubdomains(client, cfg, target)...)
	}
	if cfg.SubTakeover {
		allResults = append(allResults, modules.CheckSubdomainTakeover(client, cfg, target)...)
	}
	if cfg.RateLimitTest {
		allResults = append(allResults, modules.TestRateLimiting(client, cfg, target)...)
	}

	return allResults, totalURLs, totalForms
}

// ── Sprint 6 helpers ──────────────────────────────────────────────────────

// runTemplate loads and executes a single YAML template against a target.
func runTemplate(client *http.Client, tmplPath, target string) []core.ScanResult {
	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Printf("  \033[31m[!] Template %s: %v\033[0m\n", tmplPath, err)
		return nil
	}
	defer f.Close()

	bp, err := template.Load(f)
	if err != nil {
		fmt.Printf("  \033[31m[!] Blueprint %s: %v\033[0m\n", tmplPath, err)
		return nil
	}

	fmt.Printf("  \033[36m[BLUEPRINT] %s (%s)\033[0m\n", bp.ID, bp.Brief.Title)

	find, err := bp.Run(client, target, nil)
	if err != nil {
		fmt.Printf("  \033[31m[!] Blueprint %s: %v\033[0m\n", tmplPath, err)
		return nil
	}

	if find.Hit {
		fmt.Printf("  \033[31m[✗ BLUEPRINT] %s hit at %s\033[0m\n", bp.ID, find.HitURL)
		return []core.ScanResult{{
			Type:      fmt.Sprintf("Blueprint Hit — %s", find.Brief.Title),
			URL:       find.HitURL,
			Method:    "GET",
			Parameter: "blueprint",
			Payload:   bp.ID,
			Severity:  find.Brief.Level,
			Evidence:  fmt.Sprintf("Blueprint %q hit: %s (HTTP %d)", bp.ID, find.Brief.Title, find.Status),
			Timestamp: time.Now(),
		}}
	}
	return nil
}

// runTemplateDir loads and executes all YAML templates in a directory.
func runTemplateDir(client *http.Client, dir, target string) []core.ScanResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("  \033[31m[!] Template dir %s: %v\033[0m\n", dir, err)
		return nil
	}

	var allResults []core.ScanResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		tmplPath := dir + "/" + entry.Name()
		res := runTemplate(client, tmplPath, target)
		allResults = append(allResults, res...)
	}
	fmt.Printf("  \033[36m[TEMPLATE] %d template(s) matched from %s\033[0m\n", len(allResults), dir)
	return allResults
}

// runFlow executes a named vulnerability chaining flow.
func runFlow(flowName, target string) []core.ScanResult {
	engine := flow.NewEngine()

	switch flowName {
	case "idor-sqli":
		engine.BuildIDORSQliFlow()
	case "ssrf-cmdi":
		engine.BuildSSRFToCMDI()
	case "lfi-logpoison":
		engine.BuildLFItoLogPoison()
	default:
		fmt.Printf("  \033[33m[!] Unknown flow: %s (available: idor-sqli, ssrf-cmdi, lfi-logpoison)\033[0m\n", flowName)
		return nil
	}

	fmt.Printf("  \033[36m[FLOW] Executing %s pipeline\033[0m\n", flowName)
	findings := engine.Run()

	stats := engine.Stats()
	fmt.Printf("  \033[36m[FLOW] Complete: %d finding(s) (%d chained, %d critical, %d high)\033[0m\n",
		stats["total"], stats["chained"], stats["critical"], stats["high"])

	var results []core.ScanResult
	for _, f := range findings {
		results = append(results, core.ScanResult{
			Type:      fmt.Sprintf("Flow: %s", f.Type),
			URL:       target,
			Method:    "FLOW",
			Parameter: flowName,
			Payload:   strings.Join(f.Chain, " → "),
			Severity:  f.Severity,
			Evidence:  f.Evidence,
			Timestamp: time.Now(),
		})
	}
	return results
}
