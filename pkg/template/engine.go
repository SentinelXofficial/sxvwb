// Package template provides a YAML-driven scan blueprint engine. Users
// define Blueprints in YAML with Moves (HTTP requests), Signs (match
// conditions), and Plucks (value extractors). The engine executes each
// Move against a target, collecting Findings when Signs match.
package template

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── Blueprint types ───────────────────────────────────────────────────────

// Blueprint defines a scan template — one or more HTTP Moves with
// detection Signs and value Plucks.
type Blueprint struct {
	ID    string `yaml:"id"`
	Brief Brief  `yaml:"brief"`
	Moves []Move `yaml:"moves"`
}

// Brief holds metadata about the scan.
type Brief struct {
	Title string   `yaml:"title"`
	By    string   `yaml:"by,omitempty"`
	Level string   `yaml:"level"` // "info", "low", "medium", "high", "critical"
	About string   `yaml:"about,omitempty"`
	Label []string `yaml:"label,omitempty"`
	Score string   `yaml:"score,omitempty"`
}

// Move is one HTTP step in the blueprint. It defines where to send a
// request, what Signs to look for, and what values to Pluck.
type Move struct {
	Verb     string              `yaml:"verb,omitempty"`     // GET, POST, PUT, etc.
	To       []string            `yaml:"to"`                 // URL paths (supports {{BaseURL}})
	Head     map[string]string   `yaml:"head,omitempty"`     // request headers
	Send     string              `yaml:"send,omitempty"`      // request body
	Signs    []Sign              `yaml:"signs,omitempty"`    // detection conditions
	Plucks   []Pluck             `yaml:"plucks,omitempty"`   // value extractors
	Payloads map[string][]string `yaml:"payloads,omitempty"` // injection wordlists
	Fan      string              `yaml:"fan,omitempty"`      // "spray", "lockstep", "grid"
}

// Sign describes one detection signal in the response.
type Sign struct {
	On      string   `yaml:"on"`              // "word", "pattern", "status", "size"
	In      string   `yaml:"in,omitempty"`    // "body", "head", "full"
	Has     []string `yaml:"has,omitempty"`   // word list
	Pattern []string `yaml:"pattern,omitempty"` // regex patterns
	Status  []int    `yaml:"status,omitempty"`
	Size    []int    `yaml:"size,omitempty"`
	Need    string   `yaml:"need,omitempty"`  // "all" or "any" for multi-word
	Flip    bool     `yaml:"flip,omitempty"`   // invert match

	ready []*regexp.Regexp
}

// Pluck pulls values from responses for use in later Moves.
type Pluck struct {
	Via     string   `yaml:"via"`              // "pattern", "cookie", "head"
	From    string   `yaml:"from,omitempty"`   // "body", "head"
	Pattern []string `yaml:"pattern,omitempty"`
	As      string   `yaml:"as"`               // variable name to store as
	Capture int      `yaml:"capture,omitempty"` // regex group (default 1)

	ready []*regexp.Regexp
}

// Sack holds variables extracted from previous Moves.
type Sack map[string]string

// Find is the outcome of executing a Blueprint against a target.
type Find struct {
	ID       string
	Brief    Brief
	Hit      bool
	HitURL   string
	StepNum  int
	On       string
	Body     string
	Status   int
	Vars     Sack
	Picked   map[string]string
}

// ── Loading ───────────────────────────────────────────────────────────────

// Load reads a YAML Blueprint from a reader and validates it.
func Load(r io.Reader) (*Blueprint, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var bp Blueprint
	if err := yaml.Unmarshal(data, &bp); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if bp.ID == "" {
		return nil, fmt.Errorf("missing 'id' field")
	}
	if len(bp.Moves) == 0 {
		return nil, fmt.Errorf("blueprint %q has no moves", bp.ID)
	}
	// Pre-compile regex
	for i := range bp.Moves {
		for j := range bp.Moves[i].Signs {
			s := &bp.Moves[i].Signs[j]
			for _, r := range s.Pattern {
				re, err := regexp.Compile(r)
				if err != nil {
					return nil, fmt.Errorf("%q move %d sign pattern: %w", bp.ID, i, err)
				}
				s.ready = append(s.ready, re)
			}
		}
		for j := range bp.Moves[i].Plucks {
			p := &bp.Moves[i].Plucks[j]
			for _, r := range p.Pattern {
				re, err := regexp.Compile(r)
				if err != nil {
					return nil, fmt.Errorf("%q move %d pluck pattern: %w", bp.ID, i, err)
				}
				p.ready = append(p.ready, re)
			}
		}
	}
	return &bp, nil
}

// LoadString parses a YAML snippet directly.
func LoadString(yamlStr string) (*Blueprint, error) {
	return Load(strings.NewReader(yamlStr))
}

// ── Execution ─────────────────────────────────────────────────────────────

// Run executes the blueprint against a base URL with optional initial vars.
func (bp *Blueprint) Run(client *http.Client, baseURL string, vars Sack) (*Find, error) {
	f := &Find{
		ID:    bp.ID,
		Brief: bp.Brief,
		Vars:  make(Sack),
	}
	for k, v := range vars {
		f.Vars[k] = v
	}

	for idx, move := range bp.Moves {
		paths := resolveTos(move.To, baseURL, f.Vars)
		pCombos := fanOut(move.Payloads, move.Fan)
		if len(pCombos) == 0 {
			pCombos = []map[string]string{nil}
		}

		for _, pset := range pCombos {
			for _, path := range paths {
				resolvedPath := fill(path, f.Vars)
				for k, v := range pset {
					resolvedPath = strings.ReplaceAll(resolvedPath, "{{"+k+"}}", v)
				}

				fullURL := joinURL(baseURL, resolvedPath)
				resolvedBody := fill(move.Send, f.Vars)
				for k, v := range pset {
					resolvedBody = strings.ReplaceAll(resolvedBody, "{{"+k+"}}", v)
				}

				resp, respBody, err := doMove(client, move.Verb, fullURL, move.Head, resolvedBody, f.Vars)
				if err != nil {
					continue
				}

				// Pluck values
				for _, pluck := range move.Plucks {
					picked := runPluck(resp, respBody, pluck)
					for k, v := range picked {
						f.Vars[k] = v
					}
				}

				// Check signs
				if checkSigns(resp, respBody, move.Signs) {
					f.Hit = true
					f.HitURL = fullURL
					f.StepNum = idx
					f.On = resolvedPath
					f.Body = respBody
					f.Status = resp.StatusCode
					f.Picked = make(map[string]string)
					for _, pluck := range move.Plucks {
						for k, v := range runPluck(resp, respBody, pluck) {
							f.Picked[k] = v
						}
					}
				}
			}
		}
	}

	return f, nil
}

// ── Internal ──────────────────────────────────────────────────────────────

func resolveTos(paths []string, baseURL string, vars Sack) []string {
	resolved := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.ReplaceAll(p, "{{BaseURL}}", baseURL)
		for k, v := range vars {
			p = strings.ReplaceAll(p, "{{"+k+"}}", v)
		}
		resolved = append(resolved, p)
	}
	return resolved
}

func fanOut(payloads map[string][]string, mode string) []map[string]string {
	if len(payloads) == 0 { return nil }
	switch mode {
	case "grid":
		return cartesian(payloads)
	case "lockstep":
		return lockstep(payloads)
	default: // "spray"
		var result []map[string]string
		for name, values := range payloads {
			for _, v := range values {
				result = append(result, map[string]string{name: v})
			}
		}
		return result
	}
}

func cartesian(pl map[string][]string) []map[string]string {
	keys := make([]string, 0, len(pl))
	for k := range pl { keys = append(keys, k) }
	var result []map[string]string
	var walk func(int, map[string]string)
	walk = func(idx int, cur map[string]string) {
		if idx == len(keys) {
			clone := make(map[string]string, len(cur))
			for k, v := range cur { clone[k] = v }
			result = append(result, clone)
			return
		}
		for _, val := range pl[keys[idx]] {
			cur[keys[idx]] = val
			walk(idx+1, cur)
		}
	}
	walk(0, map[string]string{})
	return result
}

func lockstep(pl map[string][]string) []map[string]string {
	maxLen := 0
	for _, vals := range pl {
		if len(vals) > maxLen { maxLen = len(vals) }
	}
	var result []map[string]string
	for i := 0; i < maxLen; i++ {
		combo := map[string]string{}
		for k, vals := range pl {
			if i < len(vals) { combo[k] = vals[i] }
		}
		result = append(result, combo)
	}
	return result
}

func fill(s string, vars Sack) string {
	for k, v := range vars { s = strings.ReplaceAll(s, "{{"+k+"}}", v) }
	return s
}

func joinURL(base, path string) string {
	if strings.HasPrefix(path, "http") { return path }
	base = strings.TrimSuffix(base, "/")
	path = strings.TrimPrefix(path, "/")
	if path == "" { return base }
	return base + "/" + path
}

func doMove(client *http.Client, verb, rawURL string, head map[string]string, body string, vars Sack) (*http.Response, string, error) {
	verb = fill(verb, vars)
	if verb == "" { verb = "GET" }
	var bodyReader io.Reader
	if body != "" { bodyReader = strings.NewReader(body) }
	req, err := http.NewRequest(verb, rawURL, bodyReader)
	if err != nil { return nil, "", err }
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range head { req.Header.Set(k, fill(v, vars)) }
	if req.Header.Get("User-Agent") == "" { req.Header.Set("User-Agent", "sxsc/1.0") }
	if req.Header.Get("Accept") == "" { req.Header.Set("Accept", "*/*") }
	resp, err := client.Do(req)
	if err != nil { return nil, "", err }
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	return resp, string(b), nil
}

func checkSigns(resp *http.Response, body string, signs []Sign) bool {
	if len(signs) == 0 { return true }
	for _, s := range signs {
		hit := checkOne(resp, body, s)
		if s.Flip { hit = !hit }
		if !hit { return false }
	}
	return true
}

func checkOne(resp *http.Response, body string, s Sign) bool {
	switch s.On {
	case "status":
		for _, st := range s.Status {
			if resp.StatusCode == st { return true }
		}
		return false
	case "size":
		for _, sz := range s.Size {
			if len(body) == sz { return true }
		}
		return false
	case "word":
		searchIn := body
		if s.In == "head" { searchIn = flattenHead(resp.Header) }
		if s.In == "full" { searchIn = flattenHead(resp.Header) + "\n" + body }
		need := s.Need
		if need == "" { need = "any" }
		if need == "all" {
			for _, w := range s.Has {
				if !strings.Contains(searchIn, w) { return false }
			}
			return true
		}
		for _, w := range s.Has {
			if strings.Contains(searchIn, w) { return true }
		}
		return false
	case "pattern":
		searchIn := body
		if s.In == "head" { searchIn = flattenHead(resp.Header) }
		for _, re := range s.ready {
			if re.MatchString(searchIn) { return true }
		}
		return false
	}
	return false
}

func runPluck(resp *http.Response, body string, p Pluck) map[string]string {
	result := map[string]string{}
	switch p.Via {
	case "pattern":
		searchIn := body
		if p.From == "head" { searchIn = flattenHead(resp.Header) }
		for _, re := range p.ready {
			matches := re.FindStringSubmatch(searchIn)
			cap := p.Capture
			if cap < 1 { cap = 1 }
			if cap < len(matches) {
				result[p.As] = matches[cap]
				return result
			}
		}
	case "cookie":
		for _, c := range resp.Cookies() {
			if c.Name == p.As {
				result[p.As] = c.Value
				return result
			}
		}
	case "head":
		result[p.As] = resp.Header.Get(p.As)
		return result
	}
	return result
}

func flattenHead(h http.Header) string {
	var sb strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return sb.String()
}
