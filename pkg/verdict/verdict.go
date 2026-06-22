// Package verdict provides a composable signal detection system. Any scan
// module can embed a Verdict to get clue matching and value extraction.
// Pickers run first so their captured values feed downstream Clues.
package verdict

import (
	"fmt"
	"regexp"
	"strings"
)

// ── Public types ─────────────────────────────────────────────────────────

// Verdict bundles Clues (detection signals) and Pickers (value extractors).
// Embed in any request struct via `yaml:",inline"` for declarative detection.
type Verdict struct {
	Clues   []*Clue   `yaml:"clues,omitempty"`
	Pickers []*Picker `yaml:"pickers,omitempty"`
	Logic   string    `yaml:"logic,omitempty"` // "all" (default) or "any"
}

// Judgment holds the outcome of running detectors against response data.
type Judgment struct {
	Hit       bool
	Picked    bool
	ByClue    map[string][]string    // clue name → matched values
	ByPicker  map[string][]string    // picker name → extracted values
	Show      []string               // non-internal picked values for display
	Forward   map[string]interface{} // internal values fed forward to clues
}

// Clue describes one detection signal — word match, regex, status code, or content size.
type Clue struct {
	Name    string   `yaml:"name,omitempty"`
	Where   string   `yaml:"where,omitempty"`   // "body", "head", "full" — defaults to "body"
	Has     []string `yaml:"has,omitempty"`     // substrings to look for
	Pattern []string `yaml:"pattern,omitempty"` // regex patterns
	Status  []int    `yaml:"status,omitempty"`  // expected HTTP status codes
	Size    []int    `yaml:"size,omitempty"`    // expected content length
	Need    string   `yaml:"need,omitempty"`    // "all" or "any" for multi-word — default "any"
	Flip    bool     `yaml:"flip,omitempty"`    // invert the match result
	Score   int      `yaml:"score,omitempty"`   // weight (0-10), optional

	compiled []*regexp.Regexp
}

// Picker extracts values from responses — tokens, CSRF nonces, redirect URLs.
type Picker struct {
	Name    string   `yaml:"name"`
	Where   string   `yaml:"where,omitempty"`   // "body", "head", "full" — default "body"
	Pattern []string `yaml:"pattern,omitempty"` // regex with capture group
	Header  string   `yaml:"header,omitempty"`  // pick from a specific response header
	Quiet   bool     `yaml:"quiet,omitempty"`   // if true, value feeds clues but is not displayed
	Capture int      `yaml:"capture,omitempty"` // regex group (1-indexed, default 1)

	compiled []*regexp.Regexp
}

// ── Builder (fluent API) ─────────────────────────────────────────────────

// New creates an empty Verdict.
func New() *Verdict { return &Verdict{Logic: "all"} }

// WithClue adds a word-match clue.
func (v *Verdict) WithClue(name, where string, words ...string) *Verdict {
	v.Clues = append(v.Clues, &Clue{Name: name, Where: where, Has: words, Need: "any"})
	return v
}

// WithClueAll adds a word-match clue that requires all words.
func (v *Verdict) WithClueAll(name, where string, words ...string) *Verdict {
	v.Clues = append(v.Clues, &Clue{Name: name, Where: where, Has: words, Need: "all"})
	return v
}

// WithPattern adds a regex clue.
func (v *Verdict) WithPattern(name, pattern string) *Verdict {
	v.Clues = append(v.Clues, &Clue{Name: name, Where: "body", Pattern: []string{pattern}})
	return v
}

// WithStatus adds a status-code clue.
func (v *Verdict) WithStatus(name string, codes ...int) *Verdict {
	v.Clues = append(v.Clues, &Clue{Name: name, Status: codes})
	return v
}

// WithPicker adds a regex value extractor.
func (v *Verdict) WithPicker(name, pattern string, quiet bool) *Verdict {
	v.Pickers = append(v.Pickers, &Picker{Name: name, Where: "body", Pattern: []string{pattern}, Quiet: quiet})
	return v
}

// Any sets clue logic to "any" (OR).
func (v *Verdict) Any() *Verdict { v.Logic = "any"; return v }

// ── Compilation ──────────────────────────────────────────────────────────

// Ready pre-compiles all regex patterns. Call after building or unmarshaling.
func (v *Verdict) Ready() error {
	for _, c := range v.Clues {
		for _, r := range c.Pattern {
			re, err := regexp.Compile(r)
			if err != nil {
				return fmt.Errorf("clue %q regex %q: %w", c.Name, r, err)
			}
			c.compiled = append(c.compiled, re)
		}
	}
	for _, p := range v.Pickers {
		for _, r := range p.Pattern {
			re, err := regexp.Compile(r)
			if err != nil {
				return fmt.Errorf("picker %q regex %q: %w", p.Name, r, err)
			}
			p.compiled = append(p.compiled, re)
		}
	}
	if v.Logic == "" {
		v.Logic = "all"
	}
	return nil
}

// ── Execution ────────────────────────────────────────────────────────────

// Judge runs pickers first (so quiet values feed clues), then clues.
// The signals map should contain at minimum:
//
//	"body"          → response body string
//	"head"          → response header string (flattened)
//	"status_code"   → HTTP status code (int)
//	"content_length" → response body length (int)
func (v *Verdict) Judge(signals map[string]interface{}) *Judgment {
	j := &Judgment{
		ByClue:   make(map[string][]string),
		ByPicker: make(map[string][]string),
		Forward:  make(map[string]interface{}),
	}

	// Phase 1: Pickers run first — quiet values are fed into signals
	for _, p := range v.Pickers {
		vals := runPicker(signals, p)
		if len(vals) == 0 {
			continue
		}
		j.Picked = true
		j.ByPicker[p.Name] = vals
		if p.Quiet {
			j.Forward[p.Name] = vals[0]
		} else {
			j.Show = append(j.Show, vals...)
		}
	}
	for k, v := range j.Forward {
		signals[k] = v
	}

	// Phase 2: Clues — evaluate each
	if len(v.Clues) == 0 {
		j.Hit = j.Picked
		return j
	}

	allHit, anyHit := true, false
	for _, c := range v.Clues {
		snippets := runClue(signals, c)
		hit := len(snippets) > 0
		if c.Flip {
			hit = !hit
		}
		j.ByClue[c.Name] = snippets
		if hit {
			anyHit = true
		} else {
			allHit = false
		}
	}

	j.Hit = anyHit
	if v.Logic != "any" {
		j.Hit = allHit
	}
	return j
}

// ── Internal ─────────────────────────────────────────────────────────────

func peek(signals map[string]interface{}, where string) string {
	switch where {
	case "head", "header":
		if h, ok := signals["head"].(string); ok {
			return h
		}
		if h, ok := signals["header"].(string); ok {
			return h
		}
	case "full", "all":
		var sb strings.Builder
		for _, v := range signals {
			if s, ok := v.(string); ok {
				sb.WriteString(s)
				sb.WriteByte('\n')
			}
		}
		return sb.String()
	default: // "body" or empty
		if b, ok := signals["body"].(string); ok {
			return b
		}
	}
	return ""
}

func runClue(signals map[string]interface{}, c *Clue) []string {
	// Status-only clue — no text search needed
	if len(c.Status) > 0 && len(c.Has) == 0 && len(c.Pattern) == 0 {
		if code, ok := signals["status_code"].(int); ok {
			for _, s := range c.Status {
				if code == s {
					return []string{fmt.Sprintf("%d", code)}
				}
			}
		}
		return nil
	}

	// Size-only clue
	if len(c.Size) > 0 && len(c.Has) == 0 && len(c.Pattern) == 0 {
		if length, ok := signals["content_length"].(int); ok {
			for _, sz := range c.Size {
				if length == sz {
					return []string{fmt.Sprintf("%d", length)}
				}
			}
		}
		return nil
	}

	// Text-based clues (words + patterns)
	s := peek(signals, c.Where)
	if s == "" {
		return nil
	}
	need := c.Need
	if need == "" {
		need = "any"
	}

	// Patterns first — fastest to fail
	for _, re := range c.compiled {
		if vals := re.FindStringSubmatch(s); len(vals) > 0 {
			return vals
		}
	}

	// Words — AND logic
	if need == "all" && len(c.Has) > 0 {
		for _, w := range c.Has {
			if !strings.Contains(s, w) {
				return nil
			}
		}
		return c.Has
	}

	// Words — OR logic (default)
	for _, w := range c.Has {
		if strings.Contains(s, w) {
			return []string{w}
		}
	}
	return nil
}

func runPicker(signals map[string]interface{}, p *Picker) []string {
	// Header-name picker
	if p.Header != "" {
		if h, ok := signals["head"].(string); ok {
			for _, line := range strings.Split(h, "\n") {
				parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
				if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), p.Header) {
					return []string{strings.TrimSpace(parts[1])}
				}
			}
		}
		return nil
	}

	// Text-based regex picker
	s := peek(signals, p.Where)
	if s == "" {
		return nil
	}
	for _, re := range p.compiled {
		matches := re.FindAllStringSubmatch(s, -1)
		cap := p.Capture
		if cap < 1 {
			cap = 1
		}
		for _, m := range matches {
			if cap < len(m) {
				return []string{m[cap]}
			}
		}
	}
	return nil
}
