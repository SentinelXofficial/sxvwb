// Package handshake probes TLS/SSL endpoints for configuration weaknesses:
// expired certificates, self-signed certs, weak cipher suites, and outdated
// protocol versions.  Complements HTTP-level security header checks with
// transport-layer hardening assessment.
package handshake

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// SnipeResult holds the outcome of a TLS probe against a host:port pair.
type SnipeResult struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Version     string    `json:"tls_version"`
	CipherSuite string    `json:"cipher_suite"`
	CertExpiry  time.Time `json:"cert_expiry"`
	CertIssuer  string    `json:"cert_issuer"`
	CertSubject string    `json:"cert_subject"`
	SANs        []string  `json:"sans,omitempty"`
	SelfSigned  bool      `json:"self_signed"`
	Expired     bool      `json:"expired"`
	WeakCipher  bool      `json:"weak_cipher"`
	WeakProto   bool      `json:"weak_protocol"`
	Findings    []string  `json:"findings,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// ── Probing ──────────────────────────────────────────────────────────────

// Snipe connects to host:port via TLS and returns a full security assessment.
// It handles self-signed certificates gracefully (retries with verification
// disabled only when the error is specifically a verification failure).
func Snipe(host string, port int, timeout time.Duration) (*SnipeResult, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	// First attempt: full verification
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         0, // let Go negotiate the highest
	})

	if err != nil {
		// Retry with InsecureSkipVerify only for verification errors
		if isCertErr(err) {
			conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			})
		}
		if err != nil {
			return &SnipeResult{Host: host, Port: port, Error: err.Error()}, nil
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	r := &SnipeResult{
		Host:        host,
		Port:        port,
		Version:     tlsVer(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	// Certificate analysis
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		r.CertExpiry = cert.NotAfter
		r.CertSubject = cert.Subject.CommonName
		r.CertIssuer = cert.Issuer.CommonName
		r.SANs = cert.DNSNames

		now := time.Now()
		if cert.Issuer.CommonName == cert.Subject.CommonName && !cert.IsCA {
			r.SelfSigned = true
			r.Findings = append(r.Findings, "self-signed certificate (not trusted by any CA)")
		}
		if now.After(cert.NotAfter) {
			r.Expired = true
			r.Findings = append(r.Findings, "certificate has expired")
		}
		if now.Before(cert.NotBefore) {
			r.Findings = append(r.Findings, "certificate not yet valid")
		}
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysLeft >= 0 && daysLeft < 30 {
			r.Findings = append(r.Findings, fmt.Sprintf("certificate expires in %d days", daysLeft))
		}
		// Check for weak signature algorithms
		switch cert.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
			x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			r.Findings = append(r.Findings, fmt.Sprintf("weak signature algorithm: %s", cert.SignatureAlgorithm))
		}
	} else {
		r.Findings = append(r.Findings, "no certificate presented (anonymous cipher?)")
	}

	// Protocol version check
	r.WeakProto = isWeakProto(state.Version)
	if r.WeakProto {
		r.Findings = append(r.Findings, fmt.Sprintf("weak TLS version in use: %s", r.Version))
	}

	// Cipher strength check
	r.WeakCipher = isWeakCipher(state.CipherSuite)
	if r.WeakCipher {
		r.Findings = append(r.Findings, fmt.Sprintf("weak cipher negotiated: %s", r.CipherSuite))
	}

	return r, nil
}

// SnipeMany probes the standard TLS ports for a host in parallel.
func SnipeMany(host string) []*SnipeResult {
	ports := []int{443, 8443, 9443, 4443, 4343}
	type pair struct {
		r *SnipeResult
		e error
	}
	ch := make(chan pair, len(ports))
	for _, port := range ports {
		go func(p int) {
			r, err := Snipe(host, p, 5*time.Second)
			ch <- pair{r, err}
		}(port)
	}
	var results []*SnipeResult
	for i := 0; i < len(ports); i++ {
		p := <-ch
		if p.e == nil && p.r != nil && p.r.Error == "" {
			results = append(results, p.r)
		}
	}
	return results
}

// ── Classification ───────────────────────────────────────────────────────

func isWeakProto(version uint16) bool {
	return version < tls.VersionTLS12
}

func isWeakCipher(suite uint16) bool {
	name := strings.ToLower(tls.CipherSuiteName(suite))
	weak := []string{"null", "anon", "export", "des", "rc4", "3des", "seed", "idea"}
	for _, w := range weak {
		if strings.Contains(name, w) {
			return true
		}
	}
	return false
}

func isCertErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "x509:") ||
		strings.Contains(s, "certificate") ||
		strings.Contains(s, "unknown authority") ||
		strings.Contains(s, "self signed")
}

func tlsVer(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}
