// Package clutch detects race condition vulnerabilities (TOCTOU — Time of
// Check vs Time of Use). Sends concurrent requests to the same resource and
// observes whether the server processes them without proper serialization.
package clutch

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Window describes a detected race window.
type Window struct {
	URL       string        `json:"url"`
	Method    string        `json:"method"`
	Concurrent int          `json:"concurrent"`
	Status1   int           `json:"status_1"`
	Status2   int           `json:"status_2"`
	Latency1  time.Duration `json:"latency_1"`
	Latency2  time.Duration `json:"latency_2"`
	Evidence  string        `json:"evidence"`
}

// ── Detection ─────────────────────────────────────────────────────────────

// Slip sends concurrent requests to the same URL and checks for race
// conditions by comparing the responses. If two concurrent requests to a
// state-changing endpoint both succeed, a race window exists.
func Slip(client *http.Client, targetURL, cookie string, headers map[string]string) []Window {
	var results []Window

	// Strategy 1: Concurrent GET — check for inconsistent 200s
	results = append(results, testConcurrentGET(client, targetURL, headers, cookie)...)

	// Strategy 2: Concurrent POST with same data — check for duplicate creation
	results = append(results, testConcurrentPOST(client, targetURL, headers, cookie)...)

	// Strategy 3: Coupon/promo code exhaustion — send many uses simultaneously
	results = append(results, testRateRace(client, targetURL, headers, cookie)...)

	return results
}

func testConcurrentGET(client *http.Client, targetURL string, headers map[string]string, cookie string) []Window {
	var results []Window
	var wg sync.WaitGroup
	type outcome struct {
		status  int
		latency time.Duration
		body    string
	}

	concurrent := 2
	outcomes := make(chan outcome, concurrent)

	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			t0 := time.Now()
			req, _ := http.NewRequest("GET", targetURL, nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			if cookie != "" {
				req.Header.Set("Cookie", cookie)
			}
			resp, err := client.Do(req)
			elapsed := time.Since(t0)
			if err != nil {
				outcomes <- outcome{status: 0, latency: elapsed}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			outcomes <- outcome{status: resp.StatusCode, latency: elapsed, body: string(body)}
		}(i)
	}
	wg.Wait()
	close(outcomes)

	var results_ []outcome
	for o := range outcomes {
		results_ = append(results_, o)
	}

	if len(results_) >= 2 {
		a, b := results_[0], results_[1]
		// Both got 200 but different bodies → possible race
		if a.status == 200 && b.status == 200 && a.body != b.body {
			bodyDelta := len(a.body) - len(b.body)
			if bodyDelta < 0 {
				bodyDelta = -bodyDelta
			}
			if bodyDelta > 50 {
				results = append(results, Window{
					URL: targetURL, Method: "GET", Concurrent: concurrent,
					Status1: a.status, Status2: b.status,
					Latency1: a.latency, Latency2: b.latency,
					Evidence: fmt.Sprintf("concurrent GET returned different bodies (delta=%d bytes) — possible race condition on read", bodyDelta),
				})
			}
		}
	}

	return results
}

func testConcurrentPOST(client *http.Client, targetURL string, headers map[string]string, cookie string) []Window {
	var results []Window
	var wg sync.WaitGroup
	concurrent := 3

	type outcome struct {
		status  int
		latency time.Duration
	}
	outcomes := make(chan outcome, concurrent)

	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			t0 := time.Now()
			req, _ := http.NewRequest("POST", targetURL, nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			if cookie != "" {
				req.Header.Set("Cookie", cookie)
			}
			resp, err := client.Do(req)
			elapsed := time.Since(t0)
			if err != nil {
				outcomes <- outcome{status: 0, latency: elapsed}
				return
			}
			resp.Body.Close()
			outcomes <- outcome{status: resp.StatusCode, latency: elapsed}
		}(i)
	}
	wg.Wait()
	close(outcomes)

	var successCount, failCount int
	for o := range outcomes {
		if o.status >= 200 && o.status < 400 {
			successCount++
		} else {
			failCount++
		}
	}

	// If 2+ concurrent POSTs all succeeded, race on create
	if successCount >= 2 && failCount == 0 {
		results = append(results, Window{
			URL: targetURL, Method: "POST", Concurrent: concurrent,
			Evidence: fmt.Sprintf("%d/%d concurrent POSTs returned 2xx — possible race on resource creation (duplicate records, double-charge)", successCount, concurrent),
		})
	}

	return results
}

// testRateRace sends a burst to an endpoint that may enforce a per-request
// rate limit or coupon usage counter.
func testRateRace(client *http.Client, targetURL string, headers map[string]string, cookie string) []Window {
	var results []Window
	burstSize := 10
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // 5 concurrent

	type outcome struct {
		status  int
		latency time.Duration
		err     error
	}
	outcomes := make(chan outcome, burstSize)

	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			t0 := time.Now()
			req, _ := http.NewRequest("POST", targetURL, nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			if cookie != "" {
				req.Header.Set("Cookie", cookie)
			}
			resp, err := client.Do(req)
			elapsed := time.Since(t0)
			if err != nil {
				outcomes <- outcome{err: err, latency: elapsed}
				return
			}
			outcomes <- outcome{status: resp.StatusCode, latency: elapsed}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	close(outcomes)

	var maxLatency time.Duration
	var minLatency time.Duration = 999 * time.Hour
	successCount := 0
	for o := range outcomes {
		if o.err != nil {
			continue
		}
		if o.status >= 200 && o.status < 400 {
			successCount++
		}
		if o.latency > maxLatency {
			maxLatency = o.latency
		}
		if o.latency < minLatency {
			minLatency = o.latency
		}
	}

	// If all burst requests succeeded, no rate limiting — race possible
	if successCount >= burstSize/2 {
		results = append(results, Window{
			URL: targetURL, Method: "POST (burst)", Concurrent: burstSize,
			Evidence: fmt.Sprintf("%d/%d burst requests succeeded (latency range: %v - %v) — no rate limit enforcement detected", successCount, burstSize, minLatency.Round(time.Millisecond), maxLatency.Round(time.Millisecond)),
		})
	}

	return results
}

// ── Compile guards ────────────────────────────────────────────────────────
var _ = fmt.Sprintf
var _ = io.ReadAll
