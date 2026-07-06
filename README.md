<div align="center">

<img src="./logo/logo-with-title.svg" width="208">

![GitHub release](https://img.shields.io/github/v/release/marcuwynu23/surisc)
![Go version](https://img.shields.io/github/go-mod/go-version/marcuwynu23/surisc)
![License](https://img.shields.io/badge/license-Apache%202.0-blue?logo=apache)
![Build Status](https://github.com/marcuwynu23/surisc/actions/workflows/release.yml/badge.svg)
![Downloads](https://img.shields.io/github/downloads/marcuwynu23/surisc/total)

<strong>Frontend security reconnaissance from the browser's perspective.</strong>
Proactively hunts leaked API keys, hardcoded credentials, and exposed environment variables in JavaScript bundles.

[Read the full user guide →](USER-GUIDE.md)

</div>

## Table of Contents

- [What Is SuriSC?](#what-is-surisc)
- [Use Cases](#use-cases)
- [Benefits](#benefits-for-developers)
- [Advantages Over Other Tools](#advantages-over-other-tools)
- [User Guide](USER-GUIDE.md)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-commands)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [Development](#development)
- [Architecture](#architecture)

## What Is SuriSC?

**SuriSC** (`/səˈrisk/`, _suh-REESK_) is a memory-resident reconnaissance tool built specifically for frontend web security. Written in Go, it scrapes, parses, and analyzes JavaScript bundles from target URLs to detect secrets that should never reach the browser.

The name combines **suri** (Tagalog: "examine" or "analyze") with **SC** for **scan** — a tool that examines frontends by scanning their JavaScript.

### What It Does

- **Scrapes** — Discovers every `<script>` tag on a page and fetches its payload without writing files to disk
- **Detects** — 20+ secret types including AWS keys, Stripe secrets, GitHub PATs, Google API keys, and more
- **Analyzes** — Shannon entropy scoring flags high-density strings that look like real credentials
- **Profiles** — Identifies technology stack, hosting provider, CDN, CMS, SPA/PWA status, and security headers
- **Discovers** — Routes from HTML, JS, JSON, `robots.txt`, and `sitemap.xml`; probes attack-surface paths
- **Filters** — Built-in false positive suppression ignores compilation artifacts, placeholder values, and standard library internals
- **Reports** — Human-readable HUD output and machine-readable JSON with gravity scores for triage

### Why Use It?

| Problem                                         | How SuriSC Solves It                                                               |
| ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| Accidental API key commits to public JS bundles | Scans every fetched script for 20+ credential patterns with gravity scoring        |
| `import.meta.env` leaks in Vite/CRA builds      | Detects `VITE_API_URL`, `SUPER_SECRET_TOKEN`, etc.                                 |
| Source map exposure                             | Flags `.map` references that can reveal full server-side source                    |
| Unknown tech stack during recon                 | Fingerprints frontend framework, hosting, CDN, CMS, and security headers           |
| Manual route enumeration takes too long         | Extracts routes from HTML, JS, JSON, `robots.txt`, and `sitemap.xml` automatically |
| SPA fallback pages hide real endpoints          | Validates probed routes against 404 signatures to filter SPA shell responses       |

### The Philosophy

1. **Minimal setup, maximum value.** A single `-u` flag and you get actionable results. No config file required.
2. **Your process stays yours.** Works as a standalone CLI, in Docker/Podman containers, or as a CI pipeline step.
3. **Truth over noise.** Gravity scores, entropy thresholds, and false-positive filters mean every finding deserves your attention.

## Use Cases

| Scenario                     | How SuriSC Helps                                                                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Bug bounty recon**         | Point at a target URL and get a complete security posture report — leaked secrets, tech stack, hidden routes, and missing security headers |
| **Pre-deployment audit**     | Run in CI/CD against your staging server to catch secrets before they go live                                                              |
| **Third-party JS audit**     | Scan vendor scripts for hardcoded tokens that could compromise your application                                                            |
| **Vulnerability assessment** | Identify SPA/PWA technology for targeted exploit research; discover GraphQL endpoints                                                      |
| **Containerized scanning**   | Run from Docker or Podman for ephemeral, disposable scans without local installation                                                       |

## Benefits for Developers

- **Zero disk writes** — Operates entirely in RAM; leaves no forensic trace on the scanning machine
- **Concurrent by default** — Goroutine-powered engine processes multiple bundles simultaneously with rate limiting to avoid triggering WAFs
- **Browser-level evasion** — Chrome-like headers, random user agents, and configurable delays mimic real user traffic
- **False positive engineered** — Filters Base64 dictionaries, WASM headers, React validation warnings, route-like values, and placeholder strings
- **Gravity scoring** — Every finding gets a 0–10 score based on pattern confidence and Shannon entropy, so you prioritize what matters
- **Hosting-aware profiling** — Detects Vercel, Netlify, Cloudflare (Pages, Workers, Proxied), Heroku, Railway, GitHub Pages, and 12+ other providers
- **Multi-format output** — Human-friendly HUD and `-o json` for pipeline ingestion
- **Cross-platform** — Ships as Windows binary, NSIS installer, Debian package, macOS (Intel + Apple Silicon), and Docker image
- **Fast reachability check** — Validates target is live before scanning, with intelligent retry handling

## Advantages Over Other Tools

| Aspect                           | SuriSC                              | SecretScanner | TruffleHog   | WPScan        | manual         |
| -------------------------------- | ----------------------------------- | ------------- | ------------ | ------------- | -------------- |
| **Setup time**                   | ~10 seconds                         | Minutes       | Minutes      | Minutes       | Ongoing effort |
| **Memory-resident**              | Yes                                 | No            | No           | No            | N/A            |
| **Frontend framework detection** | Yes (10+ frameworks)                | No            | No           | No            | Manual         |
| **Hosting provider detection**   | Yes (15+ providers)                 | No            | No           | No            | Manual         |
| **Security header audit**        | Yes                                 | No            | No           | Yes           | Manual         |
| **SPA/PWA identification**       | Yes                                 | No            | No           | No            | Manual         |
| **Route discovery**              | Yes                                 | No            | No           | Yes           | Manual         |
| **Attack-surface probing**       | Yes                                 | No            | No           | Limited       | Manual         |
| **False-positive filters**       | Built-in per pattern                | Basic         | Basic        | Pattern-based | N/A            |
| **Gravity scoring**              | Yes                                 | No            | No           | No            | N/A            |
| **Shannon entropy analysis**     | Yes                                 | Yes           | Yes          | No            | N/A            |
| **JS bundle scraping**           | Yes                                 | No            | No           | No            | Manual         |
| **JSON output**                  | Yes                                 | Yes           | Yes          | No            | N/A            |
| **Docker/Podman support**        | Yes                                 | Yes           | Yes          | Yes           | N/A            |
| **Multi-platform binary**        | Windows, macOS, Linux (amd64+arm64) | Linux         | Linux, macOS | Linux         | N/A            |
| **NSIS installer**               | Yes                                 | No            | No           | No            | N/A            |
| **Debian package**               | Yes                                 | No            | No           | Yes (via apt) | N/A            |
| **License**                      | Apache 2.0                                 | Custom        | Apache 2.0   | GPL           | N/A            |

## Installation

### From Binary (Windows, macOS, Linux)

Download the latest release from [GitHub Releases](https://github.com/marcuwynu23/surisc/releases).

### From Source (Go)

```bash
go install github.com/marcuwynu23/surisc/cmd/surisc@latest
```

### Build from Repository

```bash
git clone https://github.com/marcuwynu23/surisc.git
cd surisc
make all
```

The binary will be placed in `dist/surisc.exe` (Windows) or `dist/surisc` (Linux/macOS).

### Docker / Podman

```bash
docker pull ghcr.io/marcuwynu23/surisc:latest
podman pull ghcr.io/marcuwynu23/surisc:latest
```

### Verify

```bash
surisc --help
# or
./dist/surisc.exe --help
```

## Quick Start

```bash
# Basic recon scan for secrets
surisc -u https://example.com

# Full target profiling (tech stack, routes, security headers)
surisc -u https://example.com -i

# JSON output for pipeline ingestion
surisc -u https://example.com -o json
```

## CLI Commands

### `-u` (Target URL)

```bash
surisc --help
```

| Flag          | Default | Description                                                    |
| ------------- | ------- | -------------------------------------------------------------- |
| `-u`          | `""`    | **Required.** Target URL to scan                               |
| `-o`          | `hud`   | Output format: `hud` (human-readable) or `json`                |
| `-i`          | `false` | Enable informative target analysis (disables secret leak scan) |
| `-i=webinfo`  | —       | Show only infrastructure/security header table                 |
| `-i=routes`   | —       | Show only discovered routes                                    |
| `-i=robots`   | —       | Show only `robots.txt` analysis                                |
| `-i=sitemaps` | —       | Show only `sitemap.xml` analysis                               |

### Examples

**Basic secret scan:**

```bash
surisc -u https://example.com
```

**Full informative profile:**

```bash
surisc -u https://example.com -i
```

**JSON output with secrets:**

```bash
surisc -u https://example.com -o json
```

**Technology stack only:**

```bash
surisc -u https://example.com -i webinfo
```

**Route discovery only:**

```bash
surisc -u https://example.com -i routes
```

## Configuration

SuriSC requires no configuration file. All options are passed as CLI flags.

| Source            | Precedence |
| ----------------- | ---------- |
| CLI flags         | Highest    |
| Built-in defaults | Lowest     |

## Example Output

```text
SuriSC Completed. Results:
--------------------------------------------------------------------------------
[!]     [GOOGLE_API_KEY]
        [SOURCE_URL]: https://example.com/assets/index.js
        [GRAVITY_SCORE]: 9.00
        [SNIPPET]: AIzaSyBLT...
--------------------------------------------------------------------------------
[!]     [IMPORT_META_LEAK]
        [SOURCE_URL]: https://example.com/assets/index.js
        [GRAVITY_SCORE]: 8.50
        [SNIPPET]: import.meta.env.VITE_BACKEND_API
```

## CI/CD Integration

### GitHub Actions (Secret Scan)

```yaml
name: Secret Scan
on:
  schedule:
    - cron: "0 6 * * 1" # Weekly Monday morning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan staging
        uses: docker://ghcr.io/marcuwynu23/surisc:latest
        with:
          args: -u https://staging.example.com -o json
```

### GitLab CI

```yaml
surisc-scan:
  image: ghcr.io/marcuwynu23/surisc:latest
  script:
    - /surisc -u https://example.com -o json
  artifacts:
    paths:
      - surisc-report.json
```

## Development

### Prerequisites

| Tool            | Version | Purpose                      |
| --------------- | ------- | ---------------------------- |
| Go              | 1.24+   | Compiler                     |
| Make            | Any     | Build automation             |
| makensis (NSIS) | Any     | Windows installer (optional) |
| fpm             | Any     | Debian packaging (optional)  |

### Commands

```bash
make all          # Build binary + installer
make exe          # Build Windows binary only
make linux        # Build Linux binary
make test         # Run all tests
make clean        # Remove build artifacts
make deb          # Build Debian package (requires fpm)
```

### Project Structure

```
surisc/
├── cmd/surisc/        # CLI entrypoint (flag parsing, output formatting)
├── internal/
│   ├── models/        # Data types (Leak, TechInsight)
│   └── scanner/       # Core scanning engine (colly scraper, regex, entropy)
├── tests/             # Integration tests
├── dist/              # Build output (gitignored)
├── docs/              # Static documentation site (HTML)
├── logo/              # SVG assets
├── installer/         # NSIS installer script
├── .github/workflows/ # CI/CD pipelines
├── Dockerfile
├── makefile
├── go.mod
└── go.sum
```

## Architecture

- **Entrypoint** (`cmd/surisc/main.go`) — Parses CLI flags, validates the target URL, calls the scanner, and renders output
- **Scraper** (`internal/scanner/scanner.go`) — Uses `colly/v2` with async goroutines to crawl HTML, fetch JS bundles, and extract routes
- **Analyzer** — Scans content with 20+ compiled regex patterns and Shannon entropy calculations; deduplicates; assigns gravity scores
- **Profiler** — Fingerprints frontend frameworks (React, Vue, Svelte, etc.), hosting providers (Vercel, Cloudflare, etc.), and security headers
- **Models** (`internal/models/models.go`) — Go structs for `Leak` (finding) and `TechInsight` (profile) with JSON serialization tags
- **Output** — HUD formatter (terminal tables) or JSON marshaler for pipeline use

---

## License

[Apache 2.0](LICENSE) — Copyright (c) 2026 Mark Wayne Menorca

A permissive license that grants you the freedom to use, modify, distribute, and sell the software, provided you include the original copyright notice. It also includes an express grant of patent rights from contributors.

Happy Coding! 🚀
