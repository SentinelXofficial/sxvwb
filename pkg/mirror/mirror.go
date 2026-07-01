// Package mirror caches and replays HTTP request/response pairs so the
// scanner can diff, validate, and re-test without hitting the target
// repeatedly. Useful for offline analysis and false-positive reduction.
package mirror

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Snapshot holds one request/response pair.
type Snapshot struct {
	ID         string
	URL        string
	Method     string
	ReqHeaders map[string]string
	ReqBody    string
	Status     int
	RespHeaders map[string]string
	RespBody   string
	Latency    time.Duration
	CapturedAt time.Time
	Tags       []string
}

// Cabinet stores and indexes all snapshots from a scan.
type Cabinet struct {
	mu      sync.RWMutex
	entries map[string]*Snapshot
	byURL   map[string][]string
	byStatus map[int][]string
	order    []string
}

// ── Factory ───────────────────────────────────────────────────────────────

// NewCabinet creates a response cache for offline analysis.
func NewCabinet() *Cabinet {
	return &Cabinet{
		entries:  make(map[string]*Snapshot),
		byURL:    make(map[string][]string),
		byStatus: make(map[int][]string),
	}
}

// ── Capture ───────────────────────────────────────────────────────────────

// Store saves a request/response pair and returns its ID.
func (c *Cabinet) Store(method, rawURL string, reqHeaders map[string]string, reqBody string, resp *http.Response, respBody string, latency time.Duration) string {
	id := hashID(method, rawURL, reqBody)
	s := &Snapshot{
		ID: id, URL: rawURL, Method: method,
		ReqHeaders: copyMap(reqHeaders), ReqBody: reqBody,
		Status: resp.StatusCode,
		RespHeaders: extractHeaders(resp), RespBody: respBody,
		Latency: latency, CapturedAt: time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[id] = s
	c.byURL[rawURL] = append(c.byURL[rawURL], id)
	c.byStatus[resp.StatusCode] = append(c.byStatus[resp.StatusCode], id)
	c.order = append(c.order, id)

	return id
}

// ── Queries ───────────────────────────────────────────────────────────────

// Get returns a snapshot by ID.
func (c *Cabinet) Get(id string) *Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[id]
}

// ByURL returns snapshots for a given URL.
func (c *Cabinet) ByURL(rawURL string) []*Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Snapshot
	for _, id := range c.byURL[rawURL] {
		if s, ok := c.entries[id]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Diff returns snapshots where the same URL returned different responses.
func (c *Cabinet) Diff(rawURL string) []struct{ A, B *Snapshot } {
	snaps := c.ByURL(rawURL)
	if len(snaps) < 2 {
		return nil
	}
	var diffs []struct{ A, B *Snapshot }
	for i := 0; i < len(snaps); i++ {
		for j := i + 1; j < len(snaps); j++ {
			if snaps[i].Status != snaps[j].Status ||
				len(snaps[i].RespBody) != len(snaps[j].RespBody) {
				diffs = append(diffs, struct{ A, B *Snapshot }{snaps[i], snaps[j]})
			}
		}
	}
	return diffs
}

// Count returns the number of stored snapshots.
func (c *Cabinet) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ── Export ────────────────────────────────────────────────────────────────

// HAR returns a basic HAR-like JSON structure of all snapshots.
func (c *Cabinet) HAR() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var entries []map[string]interface{}
	for _, id := range c.order {
		s := c.entries[id]
		if s == nil { continue }
		entries = append(entries, map[string]interface{}{
			"url":    s.URL,
			"method": s.Method,
			"status": s.Status,
			"latency_ms": s.Latency.Milliseconds(),
			"time":   s.CapturedAt.Format(time.RFC3339),
			"response_size": len(s.RespBody),
		})
	}

	return map[string]interface{}{
		"total": len(entries),
		"entries": entries,
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

func hashID(method, url, body string) string {
	h := sha256.New()
	io.WriteString(h, method)
	io.WriteString(h, url)
	io.WriteString(h, body)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m { out[k] = v }
	return out
}

func extractHeaders(resp *http.Response) map[string]string {
	out := make(map[string]string)
	for k := range resp.Header {
		out[k] = resp.Header.Get(k)
	}
	return out
}

var _ = strings.Builder{}
var _ = sync.Mutex{}
