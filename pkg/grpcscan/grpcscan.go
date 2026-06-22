// Package grpcscan probes gRPC endpoints for reflection API exposure,
// service enumeration, and misconfigurations. gRPC reflection is like
// GraphQL introspection for microservices — full service + method discovery.
package grpcscan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// ServiceDesc describes one discovered gRPC service.
type ServiceDesc struct {
	Name    string   `json:"name"`
	Methods []string `json:"methods"`
}

// GrpcFinding records a gRPC reflection finding.
type GrpcFinding struct {
	Endpoint  string
	Port      int
	Services  []ServiceDesc
	Reflection bool
	Web        bool // gRPC-Web detected
	Evidence  string
}

// ── Probes ────────────────────────────────────────────────────────────────

// commonPorts are ports where gRPC services commonly run.
var commonPorts = []int{50051, 50052, 8080, 8443, 9090, 9091, 5000, 5001}

// Probe checks common gRPC endpoints on the target. Since gRPC uses HTTP/2,
// we probe the HTTP endpoints for gRPC-Web or reflection HTTP gateways.
func Probe(client *http.Client, baseURL string) []GrpcFinding {
	var findings []GrpcFinding

	paths := []string{
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1.Health/Watch",
		"/" + baseURL + ".Describe/",
	}

	// Probe HTTP paths
	for _, path := range paths {
		fullURL := join(baseURL, path)
		status, body, grpcHeaders := probeGRPCEndpoint(client, fullURL)

		if status == 0 {
			continue
		}

		// gRPC always returns specific headers
		hasGrpcHeaders := grpcHeaders["grpc-status"] != "" ||
			grpcHeaders["grpc-message"] != "" ||
			grpcHeaders["content-type"] == "application/grpc" ||
			grpcHeaders["content-type"] == "application/grpc+proto" ||
			grpcHeaders["content-type"] == "application/grpc-web" ||
			grpcHeaders["content-type"] == "application/grpc-web+proto"

		// gRPC responds with 200 + specific body patterns even on error
		isGrpcBody := strings.Contains(strings.ToLower(body), "grpc") ||
			len(body) >= 5 && body[0] == 0 // gRPC frame starts with 0 (uncompressed)

		if hasGrpcHeaders || (status == 200 && isGrpcBody) || status == 415 {
			r := GrpcFinding{
				Endpoint:   fullURL,
				Reflection: strings.Contains(path, "reflection") || strings.Contains(path, "Describe"),
				Web:        strings.Contains(grpcHeaders["content-type"], "grpc-web"),
				Evidence:   fmt.Sprintf("HTTP %d, Content-Type: %s, grpc-status: %s", status, grpcHeaders["content-type"], grpcHeaders["grpc-status"]),
			}
			if r.Reflection {
				r.Evidence = "gRPC reflection endpoint accessible — full service enumeration possible"
			}
			findings = append(findings, r)
		}
	}

	// Probe / if gRPC-Web headers present
	if len(findings) == 0 {
		status, body, grpcHeaders := probeGRPCEndpoint(client, baseURL+"/")
		if status == 200 && strings.HasPrefix(grpcHeaders["content-type"], "application/grpc") {
			findings = append(findings, GrpcFinding{
				Endpoint: baseURL + "/",
				Evidence: fmt.Sprintf("gRPC service at root — Content-Type: %s", grpcHeaders["content-type"]),
			})
		}
		_ = body
	}

	return findings
}

func probeGRPCEndpoint(client *http.Client, fullURL string) (int, string, map[string]string) {
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(""))
	if err != nil {
		return 0, "", nil
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Accept", "application/grpc, application/grpc-web+proto")
	req.Header.Set("User-Agent", "sxsc-grpcscan/1.0")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	hdr := make(map[string]string)
	for k := range resp.Header {
		hdr[k] = resp.Header.Get(k)
	}
	return resp.StatusCode, string(body), hdr
}

// ── HTTP/2 reflection probe via REST gateway ─────────────────────────────

// ProbeRESTGateway checks if a gRPC-Gateway (REST→gRPC) is exposed.
func ProbeRESTGateway(client *http.Client, baseURL string) []string {
	var found []string

	restPaths := []string{
		"/v1/", "/v2/", "/api/v1/", "/api/v2/",
		"/swagger.json", "/swagger/v1/swagger.json",
		"/openapiv2.json", "/api/grpc-gateway/",
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, path := range restPaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			fullURL := join(baseURL, p)
			req, _ := http.NewRequest("GET", fullURL, nil)
			req.Header.Set("User-Agent", "sxsc-grpcscan/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			// gRPC-Gateway typically returns JSON with specific fields
			contentType := resp.Header.Get("Content-Type")
			if resp.StatusCode == 200 && strings.Contains(contentType, "json") {
				mu.Lock()
				found = append(found, fullURL)
				mu.Unlock()
			}

			// Also check for specific gRPC-Gateway error headers
			if resp.Header.Get("Grpc-Metadata-Content-Type") != "" || resp.Header.Get("X-Grpc-Web") == "1" {
				mu.Lock()
				found = append(found, fullURL)
				mu.Unlock()
			}
		}(path)
	}
	wg.Wait()

	if len(found) > 0 {
		fmt.Printf("  [grpc] %d REST gateway endpoint(s) found\n", len(found))
	}
	return found
}

// ── Helpers ──────────────────────────────────────────────────────────────

func join(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	path = strings.TrimPrefix(path, "/")
	return base + "/" + path
}

var _ = time.Now
var _ = fmt.Sprintf
