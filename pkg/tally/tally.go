// Package tally scores and ranks findings by combining severity, confidence,
// exploitability, and data sensitivity. Low-confidence findings get downgraded
// or marked for manual review. High-confidence findings with data leakage
// get boosted to critical.
package tally

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ── Types ────────────────────────────────────────────────────────────────

// Score is a numerical assessment of a finding's real-world impact.
type Score struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Confidence  int     `json:"confidence"`   // 0-100
	DataLeaked  bool    `json:"data_leaked"`   // did we extract actual data?
	Exploitable bool    `json:"exploitable"`   // is there a working exploit path?
	CVSS        float64 `json:"cvss"`         // 0.0-10.0
	Risk        float64 `json:"risk"`          // composite score 0-100
	Verdict     string  `json:"verdict"`      // "confirmed", "likely", "possible", "unlikely"
}

// Card holds one scored finding.
type Card struct {
	Score
	Evidence string `json:"evidence"`
	URL      string `json:"url"`
}

// Deck holds all scored findings sorted by risk.
type Deck struct {
	Cards []Card
	Stats struct {
		Critical int
		High     int
		Medium   int
		Low      int
		Info     int
		Flagged  int // marked for manual review
	}
}

// ── Scoring ──────────────────────────────────────────────────────────────

// Judge evaluates a finding and assigns a composite risk score.
func Judge(findingType, severity, evidence string, confidence int, dataLeaked, exploitable bool) *Score {
	s := &Score{
		Type:        findingType,
		Severity:    severity,
		Confidence:  clamp(confidence, 0, 100),
		DataLeaked:  dataLeaked,
		Exploitable: exploitable,
	}

	// Base CVSS from severity
	baseCVSS := severityToCVSS(severity)

	// Confidence modifier: low confidence findings get docked
	confMod := float64(s.Confidence) / 100.0

	// Data leaked boost
	dataBoost := 0.0
	if dataLeaked {
		dataBoost = 1.5
	}

	// Exploitability boost
	exploitBoost := 0.0
	if exploitable {
		exploitBoost = 1.0
	}

	s.CVSS = math.Min(baseCVSS*confMod+dataBoost+exploitBoost, 10.0)
	s.Risk = math.Min(baseCVSS*10*confMod, 100)

	// Verdict
	s.Verdict = classify(confidence, dataLeaked, exploitable)

	return s
}

// Rank sorts a list of scored findings from highest risk to lowest.
func Rank(cards []Card) *Deck {
	d := &Deck{Cards: cards}
	sort.Slice(d.Cards, func(i, j int) bool {
		return d.Cards[i].Risk > d.Cards[j].Risk
	})

	for _, c := range d.Cards {
		if c.Verdict == "possible" || c.Verdict == "unlikely" {
			d.Stats.Flagged++
		}
		switch {
		case c.Risk >= 80: d.Stats.Critical++
		case c.Risk >= 60: d.Stats.High++
		case c.Risk >= 40: d.Stats.Medium++
		case c.Risk >= 20: d.Stats.Low++
		default: d.Stats.Info++
		}
	}

	return d
}

// ── Report ────────────────────────────────────────────────────────────────

// Summary returns a one-line score summary.
func (s *Score) Summary() string {
	flag := ""
	if s.Verdict == "possible" || s.Verdict == "unlikely" {
		flag = " [REVIEW]"
	}
	return fmt.Sprintf("%s: risk=%.0f cvss=%.1f conf=%d%% leak=%v exploit=%v → %s%s",
		s.Type, s.Risk, s.CVSS, s.Confidence, s.DataLeaked, s.Exploitable, s.Verdict, flag)
}

// ── Helpers ──────────────────────────────────────────────────────────────

func severityToCVSS(s string) float64 {
	switch strings.ToUpper(s) {
	case "CRITICAL": return 9.8
	case "HIGH": return 7.5
	case "MEDIUM": return 5.5
	case "LOW": return 3.5
	default: return 1.0
	}
}

func classify(confidence int, dataLeaked, exploitable bool) string {
	if confidence >= 90 && (dataLeaked || exploitable) { return "confirmed" }
	if confidence >= 75 { return "likely" }
	if confidence >= 50 { return "possible" }
	return "unlikely"
}

func clamp(v, lo, hi int) int {
	if v < lo { return lo }
	if v > hi { return hi }
	return v
}
