# TakeIt: Blazing-Fast Subdomain Takeover Detection

[![Go Report Card](https://goreportcard.com/badge/github.com/kankburhan/takeit)](https://goreportcard.com/report/github.com/kankburhan/takeit)
[![GitHub license](https://img.shields.io/github/license/kankburhan/takeit)](https://github.com/kankburhan/takeit/blob/main/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

**TakeIt** is a fast, accurate subdomain takeover detection tool for security professionals and bug bounty hunters. Powered by the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) fingerprint database, it identifies misconfigured subdomains through CNAME chain analysis, NXDOMAIN detection, HTTP fingerprinting, and wildcard DNS awareness.

---

## Features

- **CNAME Chain Resolution** — Follows full CNAME chains (up to 10 hops) and checks every hop against fingerprints
- **Accurate NXDOMAIN Detection** — Uses `net.LookupHost` for reliable dangling record detection
- **HTTP Fingerprint Matching** — Case-insensitive body and status code matching with size-limited reads
- **Wildcard DNS Detection** — Flags wildcard DNS parents to reduce false positives
- **Service Identification** — Shows exactly which service (GitHub Pages, S3, Azure, etc.) is vulnerable
- **JSON Output** — JSON lines output for easy integration with `jq` and other pipeline tools
- **Custom DNS Resolver** — Use any DNS resolver (Cloudflare, Google, internal)
- **Multiple Input Methods** — Stdin, file (`-l`), or command-line argument — can be combined
- **Domain Deduplication** — Automatically skips duplicate domains
- **Retry Logic** — Automatic retry on transient DNS/HTTP failures
- **Realistic User-Agent** — Avoids WAF blocking with browser-like UA
- **Concurrent Scanning** — Configurable thread count for high-speed scanning

---

## Installation

### Prebuilt Binaries
Download the latest release from the [Releases](https://github.com/kankburhan/takeit/releases) page.

### Install with Go
```bash
go install github.com/kankburhan/takeit@latest
```

### Build from Source
```bash
git clone https://github.com/kankburhan/takeit.git
cd takeit
go build -o takeit
```

---

## Usage

```
_____     _       _____ _
|_   _|   | |     |_   _| |
  | | __ _| | _____ | | | |_
  | |/ _' | |/ / _ \| | | __|
  | | (_| |   <  __/| |_| |_
  \_/\__,_|_|\_\___\___/ \__|
                by kankburhan

Usage:
  takeit [flags] <domain>
  cat domains.txt | takeit [flags]

Flags:
  -l  string     File containing list of domains
  -t  int        Number of threads (default 10)
  -timeout int   HTTP timeout in seconds (default 10)
  -r  string     Custom DNS resolver (e.g., 1.1.1.1 or 1.1.1.1:53)
  -o  string     Output file for results
  -f  string     Filter output (e.g., potential)
  -json          Output results as JSON lines
  -silent        Show only vulnerable results
  -update        Update takeit version
  -update-db     Update fingerprint database
  -v             Show version
  -h             Show help
```

---

## Examples

### Basic Scanning

```bash
# Scan a single domain
takeit example.com

# Scan from stdin
cat subdomains.txt | takeit

# Scan from a file
takeit -l subdomains.txt
```

### Advanced Usage

```bash
# 20 threads, save results to file
takeit -l subdomains.txt -t 20 -o results.txt

# JSON output, only vulnerable, pipe to jq
takeit -l subs.txt -json -silent | jq 'select(.vulnerable)'

# Custom DNS resolver (Cloudflare)
takeit -l subs.txt -r 1.1.1.1

# Silent mode — clean output, only takeovers
cat subs.txt | takeit -silent

# Combine multiple inputs
takeit -l list1.txt sub.example.com

# Custom timeout for slow targets
takeit -l subs.txt -timeout 20

# Full pipeline: subfinder -> takeit -> notify
subfinder -d example.com -silent | takeit -json -silent | notify -silent
```

### Update Fingerprints

```bash
# Update fingerprint database to latest
takeit -update-db

# Update the tool itself
takeit -update
```

---

## JSON Output Format

When using `-json`, each line is a JSON object:

```json
{
  "domain": "blog.example.com",
  "cname": "example.github.io",
  "cname_chain": ["example.github.io"],
  "vulnerable": true,
  "service": "GitHub Pages",
  "fingerprint": "There isn't a GitHub Pages site here.",
  "http_status": 404
}
```

Fields:
| Field | Description |
|-------|-------------|
| `domain` | The subdomain being checked |
| `cname` | Final resolved CNAME |
| `cname_chain` | Full CNAME resolution chain |
| `vulnerable` | Whether subdomain takeover is possible |
| `service` | Matched service name (when vulnerable) |
| `fingerprint` | Matched fingerprint string |
| `is_wildcard` | Whether parent domain has wildcard DNS |
| `http_status` | HTTP status code from the target |
| `error` | Error message if check failed |

---

## How It Works

1. **CNAME Chain Resolution** — Resolves the full CNAME chain for the target domain (up to 10 hops)
2. **Pattern Matching** — Checks every CNAME in the chain against known service fingerprints (case-insensitive)
3. **NXDOMAIN Verification** — For services that require it, verifies the CNAME target returns NXDOMAIN via `net.LookupHost`
4. **HTTP Fingerprinting** — Fetches HTTP response (HTTPS first, then HTTP) and matches status code + body content
5. **Wildcard Detection** — Tests if the parent domain has wildcard DNS to flag potential false positives
6. **Result Reporting** — Reports vulnerable domains with the matched service name and confidence indicators

---

## Contributions Welcome!

TakeIt is open-source and we welcome contributions. Whether you're fixing bugs, adding features, or improving documentation — send us a PR!

---

## License

TakeIt is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

TakeIt is intended for **educational purposes** and **authorized security testing only**. Unauthorized use of this tool is strictly prohibited. Always ensure you have permission before scanning any domain.
