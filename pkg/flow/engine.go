package flow

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Node represents one scan module in the flow pipeline.
type Node struct {
	Name     string   // unique node identifier
	Module   string   // scan module name (e.g. "sqli", "xss", "idor", "ssrf")
	Input    string   // data from previous node(s) to feed in
	Depends  []string // node names this node depends on
	Args     map[string]string // extra arguments for the module

	// Runtime state
	Status   NodeStatus
	Result   []Finding
	Output   map[string]string // extracted data for downstream nodes
}

// NodeStatus tracks a node's execution state.
type NodeStatus int

const (
	NodePending NodeStatus = iota
	NodeRunning
	NodeCompleted
	NodeSkipped
	NodeFailed
)

// Finding is a simplified vulnerability record for flow-chained results.
type Finding struct {
	Type      string
	Severity  string
	URL       string
	Parameter string
	Evidence  string
	Chain     []string // list of node names that led to this finding
}

// Runner is a callback that executes a scan module and returns findings.
// The flow engine calls this for each node; the caller wires real modules.
type Runner func(module string, url string, upstream map[string]string) []Finding

// Engine executes a DAG (Directed Acyclic Graph) of scan nodes,
// where output from one node feeds input to downstream nodes.
// Set Runner to wire real scan modules into the pipeline.
type Engine struct {
	nodes  map[string]*Node
	mu     sync.RWMutex
	Runner Runner
}

// NewEngine creates an empty flow engine.
func NewEngine() *Engine {
	return &Engine{nodes: make(map[string]*Node)}
}

// AddNode registers a node in the flow.
func (e *Engine) AddNode(n *Node) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.nodes[n.Name]; exists {
		return fmt.Errorf("node %q already exists", n.Name)
	}
	e.nodes[n.Name] = n
	return nil
}

// BuildPipeline creates a linear pipeline from a list of node names.
// Example: ["discover", "idor", "sqli"] → IDOR extracts numeric IDs, SQLi injects them.
func (e *Engine) BuildPipeline(names ...string) error {
	for i, name := range names {
		n := &Node{
			Name:   name,
			Status: NodePending,
		}
		if i > 0 {
			n.Depends = []string{names[i-1]}
		}
		if err := e.AddNode(n); err != nil {
			return err
		}
	}
	return nil
}

// BuildIDORSQliFlow creates a flow that extracts IDs via IDOR probing and
// then tests those IDs as SQL injection points.
func (e *Engine) BuildIDORSQliFlow() error {
	if err := e.AddNode(&Node{
		Name:   "id_discovery",
		Module: "idor",
		Status: NodePending,
	}); err != nil {
		return err
	}
	if err := e.AddNode(&Node{
		Name:    "sqli_on_ids",
		Module:  "sqli",
		Depends: []string{"id_discovery"},
		Input:   "id_discovery.ids",
		Status:  NodePending,
	}); err != nil {
		return err
	}
	return nil
}

// BuildSSRFToCMDI creates a flow that chains SSRF discovery → command injection
// on internal services found via SSRF.
func (e *Engine) BuildSSRFToCMDI() error {
	if err := e.AddNode(&Node{
		Name:   "ssrf_discover",
		Module: "ssrf",
		Status: NodePending,
	}); err != nil {
		return err
	}
	if err := e.AddNode(&Node{
		Name:    "cmdi_on_internal",
		Module:  "cmdi",
		Depends: []string{"ssrf_discover"},
		Input:   "ssrf_discover.internal_urls",
		Status:  NodePending,
	}); err != nil {
		return err
	}
	return nil
}

// BuildLFItoLogPoison creates a flow that chains LFI → log file poisoning.
func (e *Engine) BuildLFItoLogPoison() error {
	if err := e.AddNode(&Node{
		Name:   "lfi_discover",
		Module: "lfi",
		Status: NodePending,
	}); err != nil {
		return err
	}
	if err := e.AddNode(&Node{
		Name:    "log_poison",
		Module:  "lfi_advanced",
		Depends: []string{"lfi_discover"},
		Input:   "lfi_discover.vuln_params",
		Status:  NodePending,
	}); err != nil {
		return err
	}
	return nil
}

// Run executes the flow DAG in dependency order. Each node runs only after
// all its dependencies have completed.
func (e *Engine) Run() []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var allFindings []Finding
	completed := make(map[string]bool)
	remaining := make(map[string]*Node)
	for name, n := range e.nodes {
		remaining[name] = n
	}

	for len(remaining) > 0 {
		var ready []string
		for name, n := range remaining {
			depsDone := true
			for _, dep := range n.Depends {
				if !completed[dep] {
					depsDone = false
					break
				}
			}
			if depsDone {
				ready = append(ready, name)
			}
		}

		if len(ready) == 0 {
			// Circular dependency or stuck — break
			fmt.Println("  \033[33m[FLOW] Warning: circular dependency detected, breaking\033[0m")
			break
		}

		// Execute ready nodes (sequentially for simplicity; could be concurrent for independent nodes)
		for _, name := range ready {
			node := remaining[name]
			node.Status = NodeRunning
			fmt.Printf("  \033[36m[FLOW] Running %s (%s)\033[0m\n", node.Name, node.Module)

			// Simulate execution — in production, this would call the actual scan module
			findings := e.executeNode(node)
			node.Result = findings
			for i := range findings {
				findings[i].Chain = append([]string{node.Name}, findings[i].Chain...)
			}
			allFindings = append(allFindings, findings...)

			// Extract output data for downstream nodes
			node.Output = e.extractOutput(node, findings)

			node.Status = NodeCompleted
			completed[name] = true
			delete(remaining, name)

			if len(findings) > 0 {
				fmt.Printf("  \033[33m[FLOW] %s → %d finding(s)\033[0m\n", node.Name, len(findings))
			}
		}
	}

	// Enrich findings with chain information
	for i := range allFindings {
		allFindings[i].Evidence = buildChainEvidence(allFindings[i])
	}

	return allFindings
}

// executeNode runs a single node's scan module. If a Runner is registered,
// it delegates to the runner for real module execution. Otherwise, it falls
// back to placeholder data so the flow can still be tested without modules.
func (e *Engine) executeNode(node *Node) []Finding {
	// Gather upstream data for chaining
	var upstream map[string]string
	for _, dep := range node.Depends {
		if depNode, ok := e.nodes[dep]; ok && len(depNode.Output) > 0 {
			if upstream == nil { upstream = make(map[string]string) }
			for k, v := range depNode.Output { upstream[k] = v }
		}
	}

	// Use real runner if wired
	if e.Runner != nil {
		return e.Runner(node.Module, node.Input, upstream)
	}

	// Fallback: chain-aware placeholder
	chainPrefix := ""
	if len(upstream) > 0 { chainPrefix = "(Flow-Chained) " }
	switch {
	case strings.Contains(node.Module, "sqli"):
		return []Finding{{Type: chainPrefix + "SQL Injection", Severity: "CRITICAL", Evidence: "via flow chain"}}
	case strings.Contains(node.Module, "idor"):
		return []Finding{{Type: chainPrefix + "IDOR", Severity: "HIGH", Evidence: "via flow chain"}}
	case strings.Contains(node.Module, "ssrf"):
		return []Finding{{Type: chainPrefix + "SSRF", Severity: "HIGH", Evidence: "via flow chain"}}
	case strings.Contains(node.Module, "cmdi"):
		return []Finding{{Type: chainPrefix + "Command Injection", Severity: "CRITICAL", Evidence: "via flow chain"}}
	case strings.Contains(node.Module, "lfi") && strings.Contains(node.Module, "poison"):
		return []Finding{{Type: chainPrefix + "RCE via Log Poisoning", Severity: "CRITICAL", Evidence: "via flow chain"}}
	case strings.Contains(node.Module, "lfi"):
		return []Finding{{Type: chainPrefix + "LFI", Severity: "HIGH", Evidence: "via flow chain"}}
	}
	return nil
}

// extractOutput extracts key-value data from a node's findings for downstream use.
func (e *Engine) extractOutput(node *Node, findings []Finding) map[string]string {
	output := make(map[string]string)
	switch node.Module {
	case "idor", "id_discovery":
		for _, f := range findings {
			if strings.Contains(f.Type, "IDOR") {
				output["ids"] = f.Parameter
				output["id_value"] = f.Evidence
			}
		}
	case "ssrf", "ssrf_discover":
		for _, f := range findings {
			if strings.Contains(f.Type, "SSRF") {
				output["internal_urls"] = f.Evidence
			}
		}
	case "lfi", "lfi_discover":
		for _, f := range findings {
			if strings.Contains(f.Type, "LFI") {
				output["vuln_params"] = f.Parameter
				output["lfi_path"] = f.Evidence
			}
		}
	}
	return output
}

func buildChainEvidence(f Finding) string {
	if len(f.Chain) == 0 {
		return f.Evidence
	}
	return fmt.Sprintf("[Chain: %s] %s", strings.Join(f.Chain, " → "), f.Evidence)
}

// ── Stats ─────────────────────────────────────────────────────────────────

// Stats returns summary statistics for the flow run.
func (e *Engine) Stats() map[string]int {
	stats := map[string]int{
		"total":    0,
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"chained":  0,
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, n := range e.nodes {
		for _, f := range n.Result {
			stats["total"]++
			switch f.Severity {
			case "CRITICAL":
				stats["critical"]++
			case "HIGH":
				stats["high"]++
			case "MEDIUM":
				stats["medium"]++
			case "LOW":
				stats["low"]++
			}
			if len(f.Chain) > 1 {
				stats["chained"]++
			}
		}
	}
	return stats
}

// Ensure time is used
var _ = time.Now
