# Release Notes

## v2.1.0 — PWA Detection & SPA Filtering

### Highlights

Added progressive web app (PWA) detection, improved script source handling, and smarter SPA fallback filtering for more accurate route discovery.

### What's New

- **PWA detection** — Classifies targets as PWA (manifest + service worker), Likely (one present), or No (none found)
- **Smart script handling** — Improved external vs. inline script source detection
- **SPA fallback filtering** — Attack surface probing now filters out SPA 200 HTML fallback responses, revealing only real endpoints

### Bug Fixes

- Fixed informative scope detection for more accurate technology profiling
- Improved HTML fallback detection for `robots.txt` and `sitemap.xml` — no longer misidentifies SPA HTML responses as valid files

### Documentation

- Expanded informative security posture section in README with use-case examples
