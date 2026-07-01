package output

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Progress is a thread-safe CLI progress bar with ETA.
//
// Usage:
//
//	pb := NewProgress(500, "URLs")
//	for each item:
//	    pb.Inc()
//	pb.Finish()
type Progress struct {
	total   int64
	current int64
	label   string
	started time.Time
	width   int
	mu      sync.Mutex
	closed  bool
}

// NewProgress creates a progress bar for total items labelled label.
func NewProgress(total int, label string) *Progress {
	return &Progress{
		total:   int64(total),
		label:   label,
		started: time.Now(),
		width:   30,
	}
}

// Inc increments the counter by 1 and redraws the bar.
func (p *Progress) Inc() {
	atomic.AddInt64(&p.current, 1)
	p.render()
}

// SetTotal updates the total (useful when size is known only after start).
func (p *Progress) SetTotal(n int) {
	atomic.StoreInt64(&p.total, int64(n))
}

func (p *Progress) render() {
	p.mu.Lock()
	defer p.mu.Unlock()

	cur := atomic.LoadInt64(&p.current)
	total := atomic.LoadInt64(&p.total)
	if total <= 0 {
		return
	}

	pct := float64(cur) / float64(total)
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(p.width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	elapsed := time.Since(p.started)
	var etaStr string
	switch {
	case cur <= 0:
		etaStr = "starting..."
	case cur >= total:
		etaStr = "done in " + fmtDuration(elapsed)
	default:
		eta := time.Duration(float64(elapsed) / float64(cur) * float64(total-cur))
		etaStr = "ETA: ~" + fmtDuration(eta)
	}

	fmt.Printf("\r  \033[36m[%s]\033[0m \033[33m%3.0f%%\033[0m (%d/%d %s) | %s   ",
		bar, pct*100, cur, total, p.label, etaStr)
}

// Finish draws the bar at 100% and prints a newline.
func (p *Progress) Finish() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()

	atomic.StoreInt64(&p.current, atomic.LoadInt64(&p.total))
	p.render()
	fmt.Println()
}

// fmtDuration formats a duration as human-readable (e.g. "2m30s").
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
