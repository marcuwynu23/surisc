# Release Notes

## v2.0.0 — Security Profiling

### Highlights

Major update introducing comprehensive target security profiling. SuriSC now profiles not just secrets but the entire security posture of a target.

### What's New

- **Attack surface probing** — Probes common sensitive paths (`/admin`, `/api`, `/auth`, `/dashboard`, `/graphql`) and reports reachable endpoints
- **robots.txt & sitemap.xml analysis** — Fetches and parses `robots.txt` directives and `sitemap.xml` URLs for route discovery
- **Cookie security audit** — Inspects cookies for `HttpOnly`, `Secure`, and `SameSite` flags
- **JWT detection** — Identifies JWT-like tokens from cookie names and values
- **Security headers audit** — Checks for CSP, X-Frame-Options, HSTS, and CORS headers
- **False positive tuning** — Improved filtering to reduce noise in scan results
