// Package wire builds and parses raw HTTP requests at the byte level.
// Unlike net/http which normalizes headers and rejects exotic syntax,
// wire preserves every byte — enabling smuggling tests, HTTP/0.9 probes,
// and arbitrary header injection.
package wire

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
)

// ── Types ────────────────────────────────────────────────────────────────

// Probe represents a parsed raw HTTP request. Headers preserve insertion
// order via an auxiliary slice (Go map iteration order is random).
type Probe struct {
	Verb    string
	Path    string
	Headers map[string]string
	Order   []string          // header insertion order
	Body    string
	Raw     []byte            // original bytes when built in unsafe mode
}

// ── Parsing ──────────────────────────────────────────────────────────────

// Unpack parses raw HTTP bytes into a Probe. If unsafe is true, the
// original bytes are preserved in Probe.Raw for byte-level mutation.
func Unpack(request string, unsafe bool) (*Probe, error) {
	p := &Probe{Headers: make(map[string]string)}
	rd := bufio.NewReader(strings.NewReader(request))

	// Request line
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read request line: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		p.Verb = strings.ToUpper(fields[0])
		p.Path = fields[1]
	}
	if len(fields) >= 3 && !strings.HasPrefix(fields[2], "HTTP") {
		// Some proxies send absolute URIs: GET http://host/path HTTP/1.1
		p.Path = fields[1]
	}

	// Headers — preserve order
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				p.Headers[k] = v
				p.Order = append(p.Order, k)
			}
		}
	}

	// Body
	body, _ := io.ReadAll(rd)
	p.Body = strings.TrimSuffix(string(body), "\r\n")

	if unsafe {
		p.Raw = []byte(request)
	}
	return p, nil
}

// ── Construction ─────────────────────────────────────────────────────────

// Knit builds the HTTP request bytes from the Probe. Headers are emitted
// in insertion order. Set unsafe to true to bypass any normalization.
func (p *Probe) Knit(unsafe bool) []byte {
	if unsafe && len(p.Raw) > 0 {
		return p.Raw
	}

	var b bytes.Buffer
	path := p.Path
	if path == "" {
		path = "/"
	}

	b.WriteString(p.Verb)
	b.WriteByte(' ')
	b.WriteString(path)
	b.WriteString(" HTTP/1.1\r\n")

	// Emit headers in order
	seen := make(map[string]bool, len(p.Order))
	for _, k := range p.Order {
		if v, ok := p.Headers[k]; ok {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
			seen[k] = true
		}
	}
	// Emit any headers not in the order slice
	for k, v := range p.Headers {
		if !seen[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}

	b.WriteString("\r\n")
	b.WriteString(p.Body)
	return b.Bytes()
}

// KnitPooled is like Knit but uses a buffer from a sync.Pool to reduce
// allocations in high-throughput scenarios.
var knitPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}

func (p *Probe) KnitPooled() []byte {
	buf := knitPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer knitPool.Put(buf)

	path := p.Path
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(buf, "%s %s HTTP/1.1\r\n", p.Verb, path)
	for _, k := range p.Order {
		buf.WriteString(k)
		buf.WriteString(": ")
		buf.WriteString(p.Headers[k])
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.WriteString(p.Body)

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out
}

// ── Mutation ─────────────────────────────────────────────────────────────

// Taint injects a payload into a specific part of the probe.
func (p *Probe) Taint(target, payload string) {
	switch target {
	case "host":
		p.Headers["Host"] = payload
	case "path":
		p.Path = payload
	case "body":
		p.Body = payload
	default:
		p.Headers[target] = payload
	}
}

// SmuggleCLTE builds a CL.TE request smuggling payload. The front-end
// proxy reads Content-Length, the backend reads Transfer-Encoding: chunked.
// The prefix is sent after the chunk terminator as the start of the next
// smuggled request.
func (p *Probe) SmuggleCLTE(cl int, smuggledPrefix string) []byte {
	b := p.Knit(false)
	raw := string(b)
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		return b
	}
	headers := raw[:idx]
	headers = setHeader(headers, "Content-Length", fmt.Sprintf("%d", cl))
	headers = setHeader(headers, "Transfer-Encoding", "chunked")
	return []byte(headers + "\r\n\r\n" + smuggledPrefix)
}

// SmuggleTECL builds a TE.CL request smuggling payload. The front-end
// proxy reads Transfer-Encoding, the backend reads Content-Length.
func (p *Probe) SmuggleTECL(cl int, smuggledChunk string) []byte {
	b := p.Knit(false)
	raw := string(b)
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		return b
	}
	headers := raw[:idx]
	headers = setHeader(headers, "Transfer-Encoding", "chunked")
	headers = setHeader(headers, "Content-Length", fmt.Sprintf("%d", cl))
	return []byte(headers + "\r\n\r\n" + smuggledChunk)
}

// ── Utilities ─────────────────────────────────────────────────────────────

// ToURL builds an absolute URL from the probe's Host header and path.
func (p *Probe) ToURL(scheme string) string {
	host := p.Headers["Host"]
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, p.Path)
}

// Clone returns a deep copy of the probe (safe to mutate).
func (p *Probe) Clone() *Probe {
	cp := &Probe{
		Verb:    p.Verb,
		Path:    p.Path,
		Headers: make(map[string]string, len(p.Headers)),
		Order:   make([]string, len(p.Order)),
		Body:    p.Body,
	}
	copy(cp.Order, p.Order)
	for k, v := range p.Headers {
		cp.Headers[k] = v
	}
	if len(p.Raw) > 0 {
		cp.Raw = make([]byte, len(p.Raw))
		copy(cp.Raw, p.Raw)
	}
	return cp
}

// ── Internal ─────────────────────────────────────────────────────────────

func setHeader(rawHeaders, key, value string) string {
	lines := strings.Split(rawHeaders, "\r\n")
	found := false
	lower := strings.ToLower(key)
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), lower+":") {
			lines[i] = key + ": " + value
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, key+": "+value)
	}
	return strings.Join(lines, "\r\n")
}

// Compile-time interface check
var _ = url.Parse
