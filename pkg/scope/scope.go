// Package scope renders a real-time terminal dashboard during scan
// execution. It shows active modules, finding counts per severity, a
// live progress bar, and latest findings as they arrive.
package scope

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Dash holds the runtime state of a live scan dashboard.
type Dash struct {
	mu       sync.RWMutex
	Target   string
	Modules  []ModStatus
	Total    int
	Done     int
	Findings []Finding
	Start    time.Time
	LastUpdates []string // recent log lines
}

// ModStatus tracks one module's execution.
type ModStatus struct {
	Name   string
	State  string // "wait", "run", "done", "skip"
	Hits   int
	Shots  int
}

// Finding is a live result.
type Finding struct {
	At       time.Time
	Type     string
	Severity string
	URL      string
	Evidence string
}

// ── Builder ──────────────────────────────────────────────────────────────

// NewDash creates a dashboard for a target scan.
func NewDash(target string) *Dash {
	return &Dash{
		Target: target,
		Start:  time.Now(),
	}
}

// ── Mutators ─────────────────────────────────────────────────────────────

// AddModule registers a scan module for tracking.
func (d *Dash) AddModule(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Modules = append(d.Modules, ModStatus{Name: name, State: "wait"})
}

// MarkRunning sets a module to the running state.
func (d *Dash) MarkRunning(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.Modules {
		if d.Modules[i].Name == name {
			d.Modules[i].State = "run"
			return
		}
	}
}

// MarkDone records a completed module with its findings count.
func (d *Dash) MarkDone(name string, hits int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Done++
	for i := range d.Modules {
		if d.Modules[i].Name == name {
			d.Modules[i].State = "done"
			d.Modules[i].Hits = hits
			return
		}
	}
}

// AddFinding logs a live finding as it arrives.
func (d *Dash) AddFinding(f Finding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f.At = time.Now()
	d.Findings = append(d.Findings, f)
}

// Log appends a live status line.
func (d *Dash) Log(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.LastUpdates = append(d.LastUpdates, msg)
	if len(d.LastUpdates) > 20 {
		d.LastUpdates = d.LastUpdates[1:]
	}
}

// ── Render ───────────────────────────────────────────────────────────────

// Render returns a terminal-ready string for the dashboard.
func (d *Dash) Render() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var sb strings.Builder
	elapsed := time.Since(d.Start).Round(time.Second)

	sb.WriteString("\033[2J\033[H") // clear screen, cursor home
	sb.WriteString("\033[36m")       // cyan
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\033[0m\n")

	sb.WriteString(fmt.Sprintf("\033[1msxsc — SentinelX Scanner\033[0m\n"))
	sb.WriteString(fmt.Sprintf("Target  : \033[33m%s\033[0m\n", d.Target))
	sb.WriteString(fmt.Sprintf("Elapsed : %v\n", elapsed))
	sb.WriteString(fmt.Sprintf("Modules : %d/%d complete\n\n", d.Done, len(d.Modules)))

	// Progress bar
	pct := 0
	if len(d.Modules) > 0 {
		pct = d.Done * 100 / len(d.Modules)
	}
	bar := progressBar(pct, 40)
	sb.WriteString(fmt.Sprintf("Progress: [\033[32m%s\033[0m] %d%%\n\n", bar, pct))

	// Module status grid
	sb.WriteString("\033[1mModules:\033[0m\n")
	sb.WriteString(strings.Repeat("-", 70) + "\n")
	cols := 3
	for i, m := range d.Modules {
		icon := statIcon(m.State)
		sb.WriteString(fmt.Sprintf(" %s %-18s", icon, m.Name))
		if (i+1)%cols == 0 {
			sb.WriteByte('\n')
		}
	}
	sb.WriteString("\n\n")

	// Severity summary
	critical, high, medium, low := countFindings(d.Findings)
	sb.WriteString("\033[1mFindings:\033[0m\n")
	sb.WriteString(strings.Repeat("-", 70) + "\n")
	sb.WriteString(fmt.Sprintf("  \033[31mCRITICAL: %d\033[0m  ", critical))
	sb.WriteString(fmt.Sprintf("\033[31mHIGH: %d\033[0m  ", high))
	sb.WriteString(fmt.Sprintf("\033[33mMEDIUM: %d\033[0m  ", medium))
	sb.WriteString(fmt.Sprintf("\033[32mLOW: %d\033[0m\n\n", low))

	// Latest findings (top 5)
	if len(d.Findings) > 0 {
		sb.WriteString("\033[1mLatest:\033[0m\n")
		sb.WriteString(strings.Repeat("-", 70) + "\n")
		start := 0
		if len(d.Findings) > 5 {
			start = len(d.Findings) - 5
		}
		for _, f := range d.Findings[start:] {
			color := sevColor(f.Severity)
			sb.WriteString(fmt.Sprintf("  %s[%s]%s %s — %s\n",
				color, f.Severity, rst, f.Type, truncateURL(f.URL, 30)))
		}
	}

	// Footer
	sb.WriteString(strings.Repeat("-", 70) + "\n")
	sb.WriteString("\033[90mPress Ctrl+C to stop scan\033[0m\n")

	return sb.String()
}

// ── Helpers ──────────────────────────────────────────────────────────────

func statIcon(state string) string {
	switch state {
	case "run": return "\033[33m>\033[0m"
	case "done": return "\033[32m*\033[0m"
	case "skip": return "\033[90m-\033[0m"
	default: return "\033[90m.\033[0m"
	}
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL", "HIGH": return "\033[31m"
	case "MEDIUM": return "\033[33m"
	case "LOW": return "\033[32m"
	default: return "\033[36m"
	}
}

func countFindings(fs []Finding) (c, h, m, l int) {
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL": c++
		case "HIGH": h++
		case "MEDIUM": m++
		case "LOW": l++
		}
	}
	return
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	if filled > width { filled = width }
	return strings.Repeat("=", filled) + strings.Repeat("-", width-filled)
}

func truncateURL(u string, n int) string {
	if len(u) <= n { return u }
	return u[:n-3] + "..."
}

const rst = "\033[0m"
