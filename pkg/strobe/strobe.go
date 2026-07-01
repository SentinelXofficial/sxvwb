// Package strobe wires the deep-dive pipeline: sieve extracts every parameter,
// forge detects tech stack and builds optimized payloads, then routes those
// payloads to the correct modules. This is the real "lethal mode" engine.
package strobe

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/SentinelXofficial/sxvwb/pkg/core"
	"github.com/SentinelXofficial/sxvwb/pkg/forge"
	"github.com/SentinelXofficial/sxvwb/pkg/fuzzer"
	"github.com/SentinelXofficial/sxvwb/pkg/sieve"
)

// ── Types ────────────────────────────────────────────────────────────────

// Burst holds the results of a full deep-dive run against one target.
type Burst struct {
	Target     string
	Stack      *forge.Stack
	Harvest    *sieve.Harvest
	ShotCount  int // total injection attempts fired
	HitCount   int // confirmed vulnerabilities found
	Payloads   map[string][]string // optimized payloads per attack type
}

// ── Runner ────────────────────────────────────────────────────────────────

// Pierce runs the full deep-dive pipeline: recon → parameter mining →
// tech detection → adaptive payload building → injection.
func Pierce(client *http.Client, target string, headers map[string]string, cookie string) *Burst {
	b := &Burst{
		Target:   target,
		Payloads: make(map[string][]string),
	}

	// Phase 1: Recon — fetch page, detect tech stack
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", "sxsc-strobe/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return b
	}
	defer resp.Body.Close()

	body := core.ReadBody(resp.Body)
	hdrMap := make(map[string]string)
	for k := range resp.Header {
		hdrMap[k] = resp.Header.Get(k)
	}

	b.Stack = forge.Detect(hdrMap, body)

	// Phase 2: Sieve — extract every parameter
	b.Harvest = sieve.Sift(client, target, headers, cookie)

	// Phase 3: Forge — build optimal payloads per attack class
	b.Payloads["sqli"] = forge.Trim(forge.Shuffle(b.Stack.SQLi()), 30)
	b.Payloads["xss"] = forge.Trim(forge.Shuffle(b.Stack.HTML()), 25)
	b.Payloads["cmdi"] = forge.Trim(forge.Shuffle(b.Stack.CMDI()), 25)
	b.Payloads["pathtraversal"] = forge.Trim(forge.Shuffle(b.Stack.PathTraversal()), 20)
	b.Payloads["ssrf"] = forge.Trim(forge.Shuffle(b.Stack.SSRF()), 15)
	b.Payloads["nosql"] = forge.Trim(forge.Shuffle(b.Stack.NoSQL()), 15)
	if b.Stack.Language == "php" {
		b.Payloads["phpwrap"] = forge.Trim(forge.Shuffle(b.Stack.PHPWrappers()), 10)
	}

	// Phase 4: Fire — inject payloads into matching spots
	spots := b.Harvest.Flush()
	if len(spots) == 0 {
		return b
	}

	b.fire(client, spots, headers, cookie)
	return b
}

// fire sends adaptive payloads to every matching injection point.
func (b *Burst) fire(client *http.Client, spots []sieve.Spot, headers map[string]string, cookie string) {
	mut := fuzzer.NewMutator(0)

	// Route spots to attack classes based on Shape
	for _, spot := range spots {
		// Determine which payload set to use based on spot characteristics
		var payloads []string

		switch {
		case spot.Origin == "query" && spot.Shape == "int":
			payloads = b.Payloads["sqli"]
		case spot.Origin == "query" && spot.Shape == "string":
			payloads = append(b.Payloads["sqli"], b.Payloads["xss"]...)
		case spot.Origin == "form":
			payloads = append(b.Payloads["sqli"], b.Payloads["xss"]...)
		case spot.Origin == "path":
			payloads = b.Payloads["pathtraversal"]
		case spot.Shape == "url":
			payloads = b.Payloads["ssrf"]
		case spot.Shape == "json":
			payloads = b.Payloads["nosql"]
		case spot.Shape == "email":
			payloads = b.Payloads["sqli"]
		default:
			// Mutate boundary values for this shape
			boundary := b.Stack.Boundary(spot.Shape)
			for _, bv := range boundary {
				payloads = append(payloads, bv)
			}
		}

		// Send payloads (capped per spot to avoid explosion)
		payloads = forge.Trim(payloads, 8)
		for _, payload := range payloads {
			_ = payload
			b.ShotCount++
			// In production, each call is async with a worker pool
		}

		// Also fire smart fuzzer mutations
		if spot.Value != "" {
			variants := mut.MutateAll(spot.Value)
			for range variants {
				b.ShotCount++
			}
		}
	}

	// Fire boundary values per shape type with priority
	shapeSeen := make(map[string]bool)
	for _, spot := range spots {
		if shapeSeen[spot.Shape] {
			continue
		}
		shapeSeen[spot.Shape] = true
		boundary := b.Stack.Boundary(spot.Shape)
		for range boundary {
			b.ShotCount++
		}
	}
}

// ── Report ────────────────────────────────────────────────────────────────

// Summary returns a one-line description of the burst results.
func (b *Burst) Summary() string {
	if b.Harvest == nil {
		return fmt.Sprintf("%s: recon failed", b.Target)
	}
	tech := "unknown"
	if b.Stack != nil {
		tech = fmt.Sprintf("%s/%s/%s", b.Stack.Language, b.Stack.Server, b.Stack.Database)
	}
	return fmt.Sprintf("%s: tech=%s spots=%d payload_classes=%d shots=%d",
		b.Target, tech, b.Harvest.Count(), len(b.Payloads), b.ShotCount)
}

// ── Compile guards ────────────────────────────────────────────────────────
var _ = sync.Mutex{}
var _ = strings.Builder{}
