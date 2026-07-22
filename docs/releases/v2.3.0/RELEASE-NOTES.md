# Release Notes

## v2.3.0 — Frontend Security Auditing & Client-Side Secret Detection

### Highlights

Minor release adding frontend security auditing (CSP, CORS, cookies, SRI, XSS, open redirect, insecure forms, vulnerable CDN), client-side storage token detection, response header API key scanning, fingerprint state management library detection, and a comprehensive test suite for the scanner. All historical release notes have been rewritten in a user-friendly format.

### What's New

#### Secret Detection

- **Client-side storage token detection** — Scans `localStorage`, `sessionStorage`, and `IndexedDB` references for stored tokens, secrets, and sensitive identifiers
- **Fingerprint state management library detection** — Identifies state management libs (Redux, Zustand, Pinia, Vuex, etc.) used in client-side apps
- **Response header API key scanning** — Scans response headers for exposed API keys and secrets

#### Frontend Security Auditing

- **CSP audit** — Evaluates Content-Security-Policy headers for weaknesses (missing directives, unsafe-inline, unsafe-eval, missing nonces)
- **CORS audit** — Checks Cross-Origin Resource Sharing policies for overly permissive configurations
- **Cookie security audit** — Inspects cookies for missing `HttpOnly`, `Secure`, and `SameSite` flags
- **SRI verification** — Detects missing Subresource Integrity attributes on script and link tags
- **XSS vulnerability scanning** — Probes endpoints for reflected XSS vulnerabilities
- **Open redirect detection** — Identifies endpoints that allow unvalidated redirects
- **Insecure form detection** — Flags forms submitted over HTTP instead of HTTPS
- **Vulnerable CDN detection** — Identifies outdated or known-vulnerable CDN libraries

#### Engine Improvements

- **Comprehensive test suite** — Added thorough test coverage for scanner components, including secret detection, fingerprinting, and auditing modules

### Documentation

- Rewrote all historical release notes (v1.0.0 through v2.2.0-next) in a consistent, user-friendly format
- Added missing release notes for v2.2.0-next, v2.2.0, v2.1.1, v2.1.0, v2.0.0, v1.1.6, v1.1.4, v1.1.1, v1.0.1, v1.0.0

### Maintenance

- Added git-rndocs release notes generation config and template for consistent formatting

### Contributors

- Mark Wayne Buncaras Menorca (25 commits)

### Full Changelog

v2.2.0...v2.3.0

