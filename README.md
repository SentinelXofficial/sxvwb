# SentinelX VWB — Vulnerability Web Scanner

Closed-source web vulnerability scanner. Private distribution only.

## Download

| Platform | Architecture | File |
|----------|-------------|------|
| Linux | amd64 | `sxvwb-linux-amd64` |
| Linux | 386 | `sxvwb-linux-386` |
| Linux | arm64 | `sxvwb-linux-arm64` |
| macOS | amd64 | `sxvwb-darwin-amd64` |
| macOS | arm64 | `sxvwb-darwin-arm64` |
| Windows | amd64 | `sxvwb-windows-amd64.exe` |
| Windows | 386 | `sxvwb-windows-386.exe` |

See [Releases](https://github.com/SentinelXofficial/sxvwb/releases) for latest binaries and checksums.

## Usage

```bash
sxvwb -u "https://target.com"
sxvwb -u "https://target.com" --crawl --depth 3
sxvwb -l targets.txt --all --json-output results.json
sxvwb --help
```

## Restricted Domains

Scanning is **NOT** allowed on:

- All Indonesian `.id` TLDs (`.co.id`, `.go.id`, `.ac.id`, `.sch.id`, `.mil.id`, `.or.id`, `.net.id`, `.web.id`, `.my.id`, `.biz.id`, `.desa.id`, `.ponpes.id`, `.id`)
- `github.com`

The binary will refuse to scan any of these domains.

## License

Proprietary — All rights reserved.
