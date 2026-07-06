# User Guide

Comprehensive reference for SuriSC — a frontend security reconnaissance tool that hunts leaked secrets in JavaScript bundles.

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Configuration](#configuration)
- [Concepts](#concepts)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [CI/CD Integration](#cicd-integration)
- [Workflows](#workflows)

---

## Installation

### Prerequisites

| Requirement            | Notes                                                |
| ---------------------- | ---------------------------------------------------- |
| Network access         | Target must be reachable from the scanning machine   |
| No elevated privileges | SuriSC does not require root or administrator access |

### Method 1 — Binary Download

1. Go to [GitHub Releases](https://github.com/marcuwynu23/surisc/releases)
2. Download the appropriate binary for your platform:
   - Windows: `surisc-windows-amd64.exe`
   - macOS Intel: `surisc-darwin-amd64`
   - macOS Apple Silicon: `surisc-darwin-arm64`
   - Linux: Bundle via `.deb` or build from source
3. Make the binary executable (macOS/Linux):
   ```bash
   chmod +x surisc-*
   ```
4. (Optional) Move to a directory in your `PATH`.

### Method 2 — Go Install

```bash
go install github.com/marcuwynu23/surisc/cmd/surisc@latest
```

### Method 3 — Build from Source

```bash
git clone https://github.com/marcuwynu23/surisc.git
cd surisc
make all
```

Outputs:

- `dist/surisc.exe` — Windows binary
- `dist/surisc-setup.exe` — NSIS Windows installer
- `dist/surisc` — Linux binary (via `make linux`)
- `*.deb` — Debian package (via `make deb`)

### Method 4 — Docker / Podman

```bash
docker pull ghcr.io/marcuwynu23/surisc:latest
podman pull ghcr.io/marcuwynu23/surisc:latest
```

### Verify Installation

```bash
surisc --help
```

Expected output displays the available flags (`-u`, `-o`, `-i`).

---

## Quick Start

### Secret Leak Scan

```bash
surisc -u https://example.com
```

Scans all JavaScript bundles on the page. Reports every finding with its type, source URL, gravity score, and a code snippet.

### Target Profile (Informative Mode)

```bash
surisc -u https://example.com -i
```

Disables secret scanning. Instead profiles the target's technology stack, hosting provider, security headers, and discovered routes.

### JSON Output

```bash
surisc -u https://example.com -o json
```

Returns machine-readable JSON to stdout for pipeline ingestion.

---

## Command Reference

### `-u` — Target URL

**Required.** The full URL (including scheme) to scan.

```bash
surisc -u https://example.com
surisc -u https://example.com/path/to/page
```

| Flag | Default | Description                                       |
| ---- | ------- | ------------------------------------------------- |
| `-u` | `""`    | Target URL. Must include `http://` or `https://`. |

### `-o` — Output Format

Controls how results are rendered.

```bash
surisc -u https://example.com -o hud
surisc -u https://example.com -o json
```

| Flag | Default | Description                                                            |
| ---- | ------- | ---------------------------------------------------------------------- |
| `-o` | `hud`   | `hud` — human-readable terminal output; `json` — machine-readable JSON |

### `-i` — Informative Mode

Skips secret leak scanning and performs technology + security profiling instead.

```bash
surisc -u https://example.com -i          # Full profile
surisc -u https://example.com -i webinfo  # Infrastructure/security table only
surisc -u https://example.com -i routes   # Routes only
surisc -u https://example.com -i robots   # robots.txt only
surisc -u https://example.com -i sitemaps # sitemap.xml only
```

| Flag            | Default | Scope                                       |
| --------------- | ------- | ------------------------------------------- |
| `-i` / `-i all` | —       | All informative sections                    |
| `-i webinfo`    | —       | Server info, security headers, cookies, JWT |
| `-i routes`     | —       | Discovered routes + attack-surface probes   |
| `-i robots`     | —       | `robots.txt` content                        |
| `-i sitemaps`   | —       | `sitemap.xml` content                       |

#### Examples by Use Case

**Technology stack reconnaissance:**

```bash
surisc -u https://example.com -i webinfo
```

Output includes a table with: Backend, Frontend, Hosting, Server, Protocol, CDN/WAF, CMS, SPA, PWA, CSP, X-Frame-Options, HSTS, ACAO, Cookie Security, and JWT Indicators.

**Full route discovery:**

```bash
surisc -u https://example.com -i routes
```

Discovers routes from HTML attributes (`href`, `src`, `action`), inline JavaScript string literals, JSON payloads, and probes common paths (`/admin`, `/api`, `/auth`, `/dashboard`, `/graphql`).

---

## Configuration

SuriSC does not use a configuration file. All settings are CLI flags.

### Precedence

1. CLI flags
2. Built-in defaults

### Built-in Defaults

| Parameter            | Default               | Notes                                        |
| -------------------- | --------------------- | -------------------------------------------- |
| Crawl parallelism    | 5 goroutines          | Configurable via `colly.LimitRule` in source |
| Request delay        | 2s random             | Between requests to avoid WAF triggers       |
| HTTP timeout         | 5s                    | Per request                                  |
| Max idle connections | 100                   | Connection pool                              |
| Max response body    | 200 KB                | Per fetch                                    |
| Browser user-agent   | Chrome 125 on Windows | Randomized per request via colly extension   |

---

## Concepts

### Gravity Score

A 0–10 confidence rating assigned to each finding. Higher scores mean higher confidence the value is a real, exploitable secret.

| Score Range | Meaning                                                               |
| ----------- | --------------------------------------------------------------------- |
| 9.0–10.0    | Near-certain leak (AWS key, Stripe live key, RSA private key)         |
| 7.0–8.9     | Likely leak (Bearer token, generic secret assignment, Google API key) |
| 5.0–6.9     | Possible leak (internal IP, map file reference)                       |
| 0.0–4.9     | Low confidence (high-entropy string with weak pattern match)          |

### Shannon Entropy

A measure of information density. SuriSC calculates:

```
H = - Σ p(i) × log₂(p(i))
```

where `p(i)` is the probability of character `i` appearing in the string.

- **Low entropy** (< 3.0): Predictable text like `"password"` or `"hello-world"`
- **Medium entropy** (3.0–4.5): Token-like strings
- **High entropy** (> 4.5): Random strings typical of real secrets

### Leak Types

| Type                            | Pattern                         | Gravity               |
| ------------------------------- | ------------------------------- | --------------------- |
| `GOOGLE_API_KEY`                | `AIza...{35}`                   | 9.0                   |
| `AWS_ACCESS_KEY`                | `AKIA...{16}`                   | 10.0                  |
| `STRIPE_SECRET_KEY`             | `sk_live_...`                   | 10.0                  |
| `GITHUB_PAT`                    | `ghp_...{36}`                   | 10.0                  |
| `SLACK_TOKEN`                   | `xox[baprs]-...`                | 9.5                   |
| `GITLAB_PAT`                    | `glpat-...`                     | 10.0                  |
| `SENDGRID_API_KEY`              | `SG....`                        | 10.0                  |
| `MAILGUN_API_KEY`               | `key-...{32}`                   | 10.0                  |
| `RESEND_API_KEY`                | `re_...{24}`                    | 10.0                  |
| `TWILIO_API_KEY`                | `SK`/`AC...{32}`                | 9.5                   |
| `SQUARE_ACCESS_TOKEN`           | `sq0...`                        | 10.0                  |
| `CLOUDFLARE_EXPOSED_CREDENTIAL` | Global key / API token          | 9.5–10.0              |
| `USER_API_TOKEN`                | Assignment with entropy > 3.0   | 8.8                   |
| `RSA_PRIVATE_KEY`               | PEM-encoded private key         | 10.0                  |
| `MAP_FILE_REFERENCE`            | `sourceMappingURL=...map`       | 5.0                   |
| `BEARER_TOKEN`                  | `Bearer ...`                    | 7.0 + (entropy × 0.5) |
| `INTERNAL_IP_ADDRESS`           | `10.x`, `172.16.x`, `192.168.x` | 6.5                   |
| `IMPORT_META_LEAK`              | `import.meta.env.*`             | 8.5                   |
| `HIGH_ENTROPY_SECRET`           | Entropy > 4.5                   | entropy × 2.0         |
| `GENERIC_SECRET_KEY`            | Pattern-matched assignment      | 8.0                   |

### Hosting Provider Detection

SuriSC detects 15+ hosting providers using response headers and content signatures:

- **Vercel** — `X-Vercel-Id` header or `vercel.app` domain
- **Netlify** — `X-Nf-Request-Id` header or `netlify.app` domain
- **Cloudflare Pages** — `_headers`/code signals and header pattern scoring
- **Cloudflare Workers** — `workers.dev` domain or `CF-Worker` header
- **Cloudflare Proxied** — `CF-Ray` header with origin server fingerprint
- **Heroku** — `Via: vegur` header or `herokuapp.com` domain
- **Railway** — `X-Railway-Request-Id` header or `railway.app` domain
- **GitHub Pages** — `Server: GitHub.com` or `github.io` domain
- **GitLab Pages** — `Server: gitlab` or `gitlab.io` domain
- **Firebase Hosting** — `X-Firebase-Request-Id` header or `web.app` domain
- **AWS Amplify** — `amplifyapp.com` domain
- **Azure Static Web Apps** — `X-Azure-Ref` header or `azurestaticapps.net` domain
- **Plus:** Render, Fly.io, Surge, Glitch

### SPA / PWA Detection

**SPA** is detected when:

- Page contains `id="root"`, `id="__next"`, `id="app"`, or `<script type="module">`
- Script paths contain `/_next/`, `/_nuxt/`, or `/@vite/`

**PWA** is classified as:

- **Yes** — manifest + service worker present
- **Likely** — manifest or service worker present
- **No** — neither found

---

## Troubleshooting

| Problem                              | Cause                                               | Fix                                                                                        |
| ------------------------------------ | --------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `target unreachable: ...`            | URL is invalid or server is down                    | Verify the URL and network connectivity                                                    |
| `Please provide a target URL`        | `-u` flag missing                                   | Add `-u https://example.com`                                                               |
| No leaks detected                    | No secrets found OR the target serves no JS bundles | Run with `-i` to verify the target is reachable and has JavaScript                         |
| HTML fallback in routes              | SPA returns 200 HTML for all paths                  | This is expected; SuriSC filters SPA fallback responses automatically                      |
| High number of false positives       | Page contains obfuscated/minified code              | Run with `-o json` and filter by gravity score (e.g., `>= 7.0`)                            |
| Slow scan                            | Target has many script tags or slow server          | Rate limiting is intentional to avoid WAF blocks; increase parallelism in source if needed |
| `unsupported protocol scheme "data"` | Inline `data:` script source                        | SuriSC skips data URIs; no action needed                                                   |
| Container exits immediately          | No `-u` flag passed                                 | Add `-u https://example.com` to the `docker run` command                                   |

---

## FAQ

**Q: Does SuriSC write anything to disk?**

A: No. It operates entirely in memory. Temporary files are never created.

**Q: Can I scan a page that requires authentication?**

A: Not directly. SuriSC does not manage cookies or sessions. You can proxy through a tool like `mitmproxy` or pre-authenticate at the network level.

**Q: How is this different from TruffleHog?**

A: TruffleHog scans git repositories. SuriSC scans live web applications — it fetches and analyzes JavaScript from target URLs in real time.

**Q: Will SuriSC trigger WAFs or rate limits?**

A: The default settings include a 2-second random delay and Chrome-like headers. For sensitive targets, consider running from a Docker container with proxy rotation.

**Q: What does the gravity score mean?**

A: A 0–10 confidence rating. 10 = almost certainly a real secret. See [Gravity Score](#gravity-score) above for the full breakdown.

**Q: Can I add custom patterns?**

A: Not via CLI. You would fork the repository and add regex patterns in `internal/scanner/scanner.go`. Contributions welcome!

**Q: Does the tool scan the entire domain?**

A: It scans the given URL and every JavaScript bundle linked from that page. It does not crawl the full domain or follow links.

**Q: What about single-page applications (SPAs)?**

A: SPAs are handled well. SuriSC identifies SPA patterns and adjusts its route probing to filter out 200 HTML fallback responses that don't represent real endpoints.

**Q: How do I scan a local file?**

A: Serve it with a local HTTP server: `python -m http.server 8000` then `surisc -u http://localhost:8000/file.html`.

**Q: Why are there no results for `-i routes`?**

A: Either the target has no discoverable routes, or all candidate routes were filtered as SPA fallbacks. Try `-i webinfo` first to confirm the target is reachable.

---

## CI/CD Integration

### GitHub Actions — Weekly Secret Scan

```yaml
name: Weekly Secret Scan
on:
  schedule:
    - cron: "0 6 * * 1"
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SuriSC
        uses: docker://ghcr.io/marcuwynu23/surisc:latest
        with:
          args: -u https://staging.example.com -o json
```

### GitLab CI — Merge Request Gate

```yaml
surisc-check:
  image: ghcr.io/marcuwynu23/surisc:latest
  script:
    - /surisc -u $TARGET_URL -o json
  except:
    - main
```

### Docker-Based CI — Generic Pipeline

```yaml
scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run --rm ghcr.io/marcuwynu23/surisc:latest -u $TARGET_URL -o json
```

---

## Workflows

### Monorepo / Staging Audit

Run as a pre-deployment step on each staging deploy:

```bash
#!/usr/bin/env bash
TARGET="$1"
surisc -u "$TARGET" -o json | jq '.[] | select(.gravity_score >= 8.0)'
if [ $? -eq 0 ]; then
  echo "High-severity secrets found! Blocking deploy."
  exit 1
fi
```

### Bug Bounty Recon

Full pipeline for target reconnaissance:

```bash
TARGET="https://example.com"
surisc -u "$TARGET" -i webinfo    # Stack + headers
surisc -u "$TARGET" -i routes     # Discover endpoints
surisc -u "$TARGET"               # Secret scan
```

### Containerized Ad-Hoc Scan

```bash
docker run --rm ghcr.io/marcuwynu23/surisc:latest -u https://example.com -o json > report.json
podman run --rm ghcr.io/marcuwynu23/surisc:latest -u https://example.com
```
