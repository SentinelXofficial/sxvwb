// Package delta compares two scan result sets to discover what changed:
// new findings, fixed vulnerabilities, and regressions.
package delta

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Change tracks one difference between two scan result sets.
type Change struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Status   string `json:"status"` // "new", "fixed", "regression"
	When     string `json:"when"`   // timestamp from the scan
}

// Report summarises the delta between two scans.
type Report struct {
	Baseline    string    `json:"baseline"`     // path to older scan
	Current     string    `json:"current"`      // path to newer scan
	ComparedAt  time.Time `json:"compared_at"`
	New         []Change  `json:"new"`          // findings in current but not baseline
	Fixed       []Change  `json:"fixed"`        // findings in baseline but not current
	Regressions []Change  `json:"regressions"`  // same URL/param, worse severity
	Summary     Summary   `json:"summary"`
}

// Summary provides counts.
type Summary struct {
	NewCritical int `json:"new_critical"`
	NewHigh     int `json:"new_high"`
	FixedTotal  int `json:"fixed_total"`
	Regressions int `json:"regressions"`
	NetChange   int `json:"net_change"` // current_count - baseline_count
}

// ── Input types ──────────────────────────────────────────────────────────

type entry struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
}

// ── Comparison ───────────────────────────────────────────────────────────

// Diff compares two JSON scan result files and returns what changed.
func Diff(baselinePath, currentPath string) (*Report, error) {
	baseline, err := load(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	current, err := load(currentPath)
	if err != nil {
		return nil, fmt.Errorf("current: %w", err)
	}

	r := &Report{
		Baseline:   baselinePath,
		Current:    currentPath,
		ComparedAt: time.Now(),
	}

	// Build lookups
	baseKeys := make(map[string]entry)
	for _, e := range baseline {
		baseKeys[key(e)] = e
	}
	curKeys := make(map[string]entry)
	for _, e := range current {
		curKeys[key(e)] = e
	}

	// New = in current but not baseline
	for k, e := range curKeys {
		if _, ok := baseKeys[k]; !ok {
			c := Change{URL: e.URL, Type: e.Type, Severity: e.Severity, Status: "new", When: e.Timestamp}
			r.New = append(r.New, c)
			switch strings.ToUpper(e.Severity) {
			case "CRITICAL": r.Summary.NewCritical++
			case "HIGH": r.Summary.NewHigh++
			}
		}
	}

	// Fixed = in baseline but not current
	for k, e := range baseKeys {
		if _, ok := curKeys[k]; !ok {
			r.Fixed = append(r.Fixed, Change{URL: e.URL, Type: e.Type, Severity: e.Severity, Status: "fixed", When: e.Timestamp})
			r.Summary.FixedTotal++
		}
	}

	// Regression = same key, severity went UP
	for k, base := range baseKeys {
		if cur, ok := curKeys[k]; ok {
			if severityRank(cur.Severity) > severityRank(base.Severity) {
				r.Regressions = append(r.Regressions, Change{URL: cur.URL, Type: cur.Type, Severity: cur.Severity, Status: "regression", When: cur.Timestamp})
				r.Summary.Regressions++
			}
		}
	}

	r.Summary.NetChange = len(current) - len(baseline)

	// Sort: new critical first, then high, then rest
	sort.Slice(r.New, func(i, j int) bool {
		return severityRank(r.New[i].Severity) > severityRank(r.New[j].Severity)
	})

	return r, nil
}

// ── Output ───────────────────────────────────────────────────────────────

// Print writes a human-readable delta report to stdout.
func (r *Report) Print() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("SCAN DELTA REPORT")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Baseline : %s\n", r.Baseline)
	fmt.Printf("Current  : %s\n", r.Current)
	fmt.Printf("Date     : %s\n\n", r.ComparedAt.Format("2006-01-02 15:04:05"))

	fmt.Printf("Net change: %+d finding(s)\n", r.Summary.NetChange)
	fmt.Printf("New       : %d (%d critical, %d high)\n", len(r.New), r.Summary.NewCritical, r.Summary.NewHigh)
	fmt.Printf("Fixed     : %d\n", r.Summary.FixedTotal)
	fmt.Printf("Regression: %d\n\n", r.Summary.Regressions)

	if len(r.New) > 0 {
		fmt.Println("--- NEW FINDINGS ---")
		for _, c := range r.New {
			color := severityColor(c.Severity)
			fmt.Printf("  %s[%s] %s%s\n", color, c.Severity, c.Type, rst)
			fmt.Printf("    URL: %s\n", c.URL)
		}
	}

	if len(r.Fixed) > 0 {
		fmt.Println("\n--- FIXED ---")
		for _, c := range r.Fixed {
			fmt.Printf("  %s[FIXED] %s%s\n", grn, c.Type, rst)
			fmt.Printf("    URL: %s\n", c.URL)
		}
	}

	if len(r.Regressions) > 0 {
		fmt.Println("\n--- REGRESSIONS ---")
		for _, c := range r.Regressions {
			fmt.Printf("  %s[REGRESSION] %s -> %s: %s%s\n", red, c.Type, c.Severity, c.URL, rst)
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 60))
}

// SaveJSON writes the delta report as JSON.
func (r *Report) SaveJSON(path string) error {
	data, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(path, data, 0600)
}

// ExitCode returns a machine-readable exit code for CI/CD.
func (r *Report) ExitCode() int {
	if r.Summary.NewCritical > 0 || r.Summary.Regressions > 0 {
		return 3
	}
	if r.Summary.NewHigh > 0 {
		return 2
	}
	if len(r.New) > 0 {
		return 1
	}
	return 0
}

// ── Helpers ──────────────────────────────────────────────────────────────

func load(path string) ([]entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Results []entry `json:"results"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return wrapper.Results, nil
}

func key(e entry) string {
	return e.Type + "|" + e.URL + "|" + e.Parameter
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL": return 5
	case "HIGH": return 4
	case "MEDIUM": return 3
	case "LOW": return 2
	case "INFO": return 1
	default: return 0
	}
}

const (
	red = "\033[31m"
	grn = "\033[32m"
	rst = "\033[0m"
)

func severityColor(s string) string {
	if strings.ToUpper(s) == "CRITICAL" || strings.ToUpper(s) == "HIGH" {
		return red
	}
	return ""
}
