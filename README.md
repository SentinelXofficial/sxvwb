# SentinelX VWB — Vulnerability Web Scanner

Closed-source web vulnerability scanner.

## Download

```bash
# Linux amd64
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-linux-amd64

# Linux 386
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-linux-386

# Linux arm64
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-linux-arm64

# macOS amd64 (Intel)
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-darwin-amd64

# macOS arm64 (Apple Silicon)
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-darwin-arm64

# Windows amd64
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-windows-amd64.exe

# Windows 386
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb-windows-386.exe

# Checksums
wget https://github.com/SentinelXofficial/sxvwb/releases/download/v1.0.0/sxvwb_checksums.txt
```

After download:

```bash
chmod +x sxvwb-linux-amd64
sudo mv sxvwb-linux-amd64 /usr/local/bin/sxvwb
```

Verify checksum:

```bash
sha256sum sxvwb-linux-amd64
# Compare with sxvwb_checksums.txt
```

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
