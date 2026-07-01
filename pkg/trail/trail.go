// Package trail writes scan results in standard industry formats for CI/CD,
// compliance reporting, and integration with security dashboards.
package trail

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ── SARIF types ──────────────────────────────────────────────────────────

// SARIFLog is the top-level SARIF v2.1.0 output structure.
type SARIFLog struct {
	Version string  `json:"version"`
	Schema  string  `json:"$schema"`
	Runs    []Run   `json:"runs"`
}

// Run represents one tool execution.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool identifies the scanner.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the scanning tool.
type Driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	InfoURI string `json:"informationUri,omitempty"`
	Rules   []Rule `json:"rules,omitempty"`
}

// Rule maps a finding type to a SARIF rule ID.
type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Result is one SARIF finding.
type Result struct {
	RuleID    string    `json:"ruleId"`
	Level     string    `json:"level"` // "error", "warning", "note", "none"
	Message   Message   `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

// Message is the human-readable description.
type Message struct {
	Text string `json:"text"`
}

// Location points to the vulnerable resource.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation,omitempty"`
}

// PhysicalLocation describes the artifact and region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region,omitempty"`
}

// ArtifactLocation identifies the file/URL.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region describes a location within the artifact.
type Region struct {
	Snippet Snippet `json:"snippet,omitempty"`
}

// Snippet holds evidence text.
type Snippet struct {
	Text string `json:"text"`
}

// ── Conversion ───────────────────────────────────────────────────────────

// FromScan converts sxsc findings into a SARIF v2.1.0 log.
func FromScan(results []ScanResult, version string) SARIFLog {
	seen := make(map[string]bool)
	var rules []Rule
	var results_ []Result

	for _, r := range results {
		ruleID := sarifRuleID(r.Type)
		if !seen[ruleID] {
			seen[ruleID] = true
			rules = append(rules, Rule{ID: ruleID, Name: r.Type})
		}

		level := sarifLevel(r.Severity)
		results_ = append(results_, Result{
			RuleID: ruleID,
			Level:  level,
			Message: Message{
				Text: fmt.Sprintf("%s: %s (parameter: %s, payload: %s)", r.Type, r.Evidence, r.Parameter, r.Payload),
			},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: r.URL},
					Region:           Region{Snippet: Snippet{Text: r.Evidence}},
				},
			}},
		})
	}

	return SARIFLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{{
			Tool: Tool{Driver: Driver{Name: "sxsc", Version: version, InfoURI: "https://github.com/SentinelXofficial/sxvwb", Rules: rules}},
			Results: results_,
		}},
	}
}

// ── Output ───────────────────────────────────────────────────────────────

// SaveSARIF writes SARIF JSON to a file.
func SaveSARIF(results []ScanResult, version, path string) error {
	log := FromScan(results, version)
	data, _ := json.MarshalIndent(log, "", "  ")
	return os.WriteFile(path, data, 0600)
}

// ExitCode returns the appropriate process exit code for CI/CD based on
// the highest severity found.
func ExitCode(results []ScanResult) int {
	worst := 0
	for _, r := range results {
		switch strings.ToUpper(r.Severity) {
		case "CRITICAL": return 3
		case "HIGH": if worst < 2 { worst = 2 }
		case "MEDIUM": if worst < 1 { worst = 1 }
		}
	}
	return worst
}

// ── Helpers ──────────────────────────────────────────────────────────────

func sarifRuleID(t string) string {
	id := strings.ToUpper(t)
	id = strings.ReplaceAll(id, " ", "_")
	id = strings.ReplaceAll(id, "-", "_")
	id = strings.ReplaceAll(id, "(", "")
	id = strings.ReplaceAll(id, ")", "")
	return "SXSC_" + id
}

func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL", "HIGH": return "error"
	case "MEDIUM": return "warning"
	case "LOW": return "note"
	default: return "none"
	}
}

// ── External types ──────────────────────────────────────────────────────

// ScanResult mirrors the core.ScanResult shape for JSON deserialization.
type ScanResult struct {
	Type      string    `json:"type"`
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	Parameter string    `json:"parameter"`
	Payload   string    `json:"payload"`
	Severity  string    `json:"severity"`
	Evidence  string    `json:"evidence"`
	Timestamp time.Time `json:"timestamp"`
}

var _ = fmt.Sprintf
