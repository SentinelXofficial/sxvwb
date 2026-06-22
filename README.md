# SentinelX VWB

Open-source web vulnerability scanner. **Community-driven. Server-enforced policy.**

Built in Go. SQLi, XSS, SSRF, LFI, Command Injection, XXE, CSRF, JWT, GraphQL, WebSocket, and 30+ more modules.

## Quick Start

### From Release (recommended)

```bash
wget https://github.com/SentinelXofficial/sxvwb/releases/latest/download/sxvwb-linux-amd64
chmod +x sxvwb-linux-amd64
sudo mv sxvwb-linux-amd64 /usr/local/bin/sxvwb
```

### From Source

```bash
git clone https://github.com/SentinelXofficial/sxvwb.git
cd sxvwb
go build -o sxvwb ./cmd/sxsc/
```

### License Key

```bash
export SXVWB_LICENSE="sxvwb-xxxxxxxxxxxxxxxx-xxxxxxxx"
```

Get a license at [api.sentinelx.me](https://api.sentinelx.me).

## Usage

```bash
sxvwb -u "https://target.com"
sxvwb -u "https://target.com" --crawl --depth 3 --waf-detect
sxvwb -l targets.txt --all --json-output results.json
sxvwb --help
```

## Architecture

```
sxvwb (this repo)          sxvwb-server (private)
  Open Source                 Validation & Policy
  -------------------         -------------------
  All scan modules            Domain blocklist
  Crawler & engine            License management
  CLI & reports               OOB callbacks
  Templates (community)       Template sync
       |                            |
       +--- /api/v1/validate ------>|
```

**Policy enforcement is server-side.** The client calls `api.sentinelx.me` before every scan. Indonesian `.id` TLDs and protected platforms are blocked at the server level.

## Features

| Category | Modules |
|----------|---------|
| Injection | SQLi (Error/Blind/Boolean), NoSQLi, Command Injection, SSTI, CRLF |
| Web | XSS (Reflected/DOM), Open Redirect, CSRF, Path Traversal, LFI/RFI |
| Infrastructure | SSRF, XXE, JWT, GraphQL, WebSocket, gRPC, HTTP Smuggling |
| Discovery | Subdomain Enum, Directory Brute, JS Endpoint Extraction |
| Defense | WAF Detection + Auto-Bypass, Security Headers Audit, Rate Limit Test |
| Advanced | Cache Poison, Proto Pollution, Deserialize, File Upload, IDOR |
| Engine | Deep Crawl, Sieve, Forge, Chain, Merge, Strobe |
| Output | HTML, JSON, CSV, Markdown, SARIF reports |

## Community Templates

Contribute scan templates to `sxvwb-templates`:

```yaml
id: cve-2024-example
info:
  name: Example CVE
  severity: critical
requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: word
        words:
          - "vulnerable"
```

## Restricted Domains

The following are blocked server-side and **cannot** be scanned:

- All Indonesian `.id` TLDs
- `github.com`

## Contributing

1. Fork this repo
2. Create feature branch
3. Add module/feature with tests
4. Submit PR

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE).

---

**Maintainer**: [SentinelX Official](https://github.com/SentinelXofficial)
**Server**: [api.sentinelx.me](https://api.sentinelx.me)
**Templates**: [sxvwb-templates](https://github.com/SentinelXofficial/sxvwb-templates)
