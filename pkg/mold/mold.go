// Package mold resolves template variables — simple {{key}} lookups and
// complex expressions like {{has(body, "admin")}} or {{upper(title)}}.
// Used by YAML blueprints, auth profiles, and any text needing dynamic fill.
package mold

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ── Public API ───────────────────────────────────────────────────────────

// Cast resolves all {{...}} placeholders in input against the variable bag.
// Simple {{key}} references are replaced directly. Complex expressions
// involving function calls like {{has(body, "admin")}} are evaluated.
func Cast(input string, bag map[string]interface{}) (string, error) {
	slots := Hunt(input, "{{", "}}")
	result := input
	for _, slot := range slots {
		val, err := Bake(slot, bag)
		if err != nil {
			return result, err
		}
		result = strings.Replace(result, "{{"+slot+"}}", fmt.Sprint(val), 1)
	}
	// Catch any remaining bare {{key}} markers that Hunt skipped
	for k, v := range bag {
		result = strings.ReplaceAll(result, "{{"+k+"}}", fmt.Sprint(v))
	}
	return result, nil
}

// Bake evaluates a single expression against the variable bag.
// Returns the bag value for simple keys, or the result of a function call.
func Bake(expr string, bag map[string]interface{}) (interface{}, error) {
	expr = strings.TrimSpace(expr)

	// Simple key lookup — no operators or parens
	if !strings.ContainsAny(expr, "()+*/=&|!<>") {
		if val, ok := bag[expr]; ok {
			return val, nil
		}
		return expr, nil
	}

	// Function call: fn(arg1, arg2, ...)
	if idx := strings.Index(expr, "("); idx >= 0 && strings.HasSuffix(expr, ")") {
		fn := strings.TrimSpace(expr[:idx])
		rawArgs := expr[idx+1 : len(expr)-1]
		args := splitArgs(rawArgs)
		resolved := make([]interface{}, len(args))
		for i, a := range args {
			a = strings.TrimSpace(a)
			a = unwrap(a)
			// Resolve nested references
			if v, ok := bag[a]; ok {
				resolved[i] = v
			} else {
				resolved[i] = a
			}
		}
		return cook(fn, resolved)
	}

	return expr, nil
}

// Hunt finds all {{...}} markers in a string. Handles nested markers.
func Hunt(data, open, close string) []string {
	exprRe := regexp.MustCompile(`[+\-*/<>=!()?&|]`)
	var found []string
	remaining := data
	for i := 0; i < 250; i++ {
		start := strings.Index(remaining, open)
		if start < 0 {
			break
		}
		remaining = remaining[start+len(open):]
		end := strings.Index(remaining, close)
		if end < 0 {
			break
		}
		inner := remaining[:end]
		if exprRe.MatchString(inner) || strings.Contains(inner, "(") {
			found = append(found, inner)
		}
		remaining = remaining[end+len(close):]
	}
	return found
}

// Fill is a convenience that casts all {{key}} patterns in a template
// string using a flat string→string bag.
func Fill(tmpl string, bag map[string]string) string {
	iface := make(map[string]interface{}, len(bag))
	for k, v := range bag {
		iface[k] = v
	}
	result, _ := Cast(tmpl, iface)
	return result
}

// ── Built-in functions ───────────────────────────────────────────────────

var kitchen = map[string]func([]interface{}) (interface{}, error){
	// String checks
	"has": func(args []interface{}) (interface{}, error) {
		if len(args) < 2 {
			return false, nil
		}
		return strings.Contains(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
	},
	"prefix": func(args []interface{}) (interface{}, error) {
		if len(args) < 2 {
			return false, nil
		}
		return strings.HasPrefix(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
	},
	"suffix": func(args []interface{}) (interface{}, error) {
		if len(args) < 2 {
			return false, nil
		}
		return strings.HasSuffix(fmt.Sprint(args[0]), fmt.Sprint(args[1])), nil
	},
	"match": func(args []interface{}) (interface{}, error) {
		if len(args) < 2 {
			return false, nil
		}
		matched, _ := regexp.MatchString(fmt.Sprint(args[0]), fmt.Sprint(args[1]))
		return matched, nil
	},

	// Transformations
	"upper": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return "", nil
		}
		return strings.ToUpper(fmt.Sprint(args[0])), nil
	},
	"lower": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return "", nil
		}
		return strings.ToLower(fmt.Sprint(args[0])), nil
	},
	"trim": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return "", nil
		}
		return strings.TrimSpace(fmt.Sprint(args[0])), nil
	},
	"swap": func(args []interface{}) (interface{}, error) {
		if len(args) < 3 {
			return "", nil
		}
		return strings.ReplaceAll(fmt.Sprint(args[0]), fmt.Sprint(args[1]), fmt.Sprint(args[2])), nil
	},
	"slice": func(args []interface{}) (interface{}, error) {
		if len(args) < 3 {
			return "", nil
		}
		s := fmt.Sprint(args[0])
		start, _ := strconv.Atoi(fmt.Sprint(args[1]))
		end, _ := strconv.Atoi(fmt.Sprint(args[2]))
		if start < 0 {
			start = 0
		}
		if end > len(s) {
			end = len(s)
		}
		if start > end {
			return "", nil
		}
		return s[start:end], nil
	},

	// Numeric
	"len": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return 0, nil
		}
		return len(fmt.Sprint(args[0])), nil
	},
	"int": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return 0, nil
		}
		v, _ := strconv.Atoi(fmt.Sprint(args[0]))
		return v, nil
	},
	"add": func(args []interface{}) (interface{}, error) {
		if len(args) < 2 {
			return 0, nil
		}
		a, _ := strconv.Atoi(fmt.Sprint(args[0]))
		b, _ := strconv.Atoi(fmt.Sprint(args[1]))
		return a + b, nil
	},

	// Random / ID generation
	"rand": func(args []interface{}) (interface{}, error) {
		n := 8
		if len(args) >= 1 {
			n, _ = strconv.Atoi(fmt.Sprint(args[0]))
		}
		return randSeq(n), nil
	},
	"uuid": func(args []interface{}) (interface{}, error) {
		return fmt.Sprintf("%x-%x-%x-%x-%x",
			rand.Int63(), rand.Int31(), rand.Int31(), rand.Int31(), rand.Int63()), nil
	},
	"ts": func(args []interface{}) (interface{}, error) {
		return time.Now().Unix(), nil
	},

	// Encoding
	"hex": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return "", nil
		}
		return fmt.Sprintf("%x", []byte(fmt.Sprint(args[0]))), nil
	},
	"urlenc": func(args []interface{}) (interface{}, error) {
		if len(args) < 1 {
			return "", nil
		}
		// Simple URL encoding
		s := fmt.Sprint(args[0])
		return strings.NewReplacer(
			" ", "%20", "!", "%21", "#", "%23", "$", "%24",
			"&", "%26", "'", "%27", "(", "%28", ")", "%29",
			"*", "%2A", "+", "%2B", ",", "%2C", "/", "%2F",
			":", "%3A", ";", "%3B", "=", "%3D", "?", "%3F",
			"@", "%40", "[", "%5B", "]", "%5D",
		).Replace(s), nil
	},

	// Array/join
	"join": func(args []interface{}) (interface{}, error) {
		if len(args) < 2 {
			return "", nil
		}
		sep := fmt.Sprint(args[0])
		parts := make([]string, len(args)-1)
		for i := 1; i < len(args); i++ {
			parts[i-1] = fmt.Sprint(args[i])
		}
		return strings.Join(parts, sep), nil
	},
}

func cook(fn string, args []interface{}) (interface{}, error) {
	if f, ok := kitchen[fn]; ok {
		return f(args)
	}
	// Unknown function — passthrough the literal template
	return fmt.Sprintf("{{%s}}", fn), nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

func splitArgs(s string) []string {
	var args []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	args = append(args, s[start:])
	return args
}

func unwrap(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

var randSrc = rand.NewSource(time.Now().UnixNano())

func randSeq(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[randSrc.Int63()%int64(len(letters))]
	}
	return string(b)
}
