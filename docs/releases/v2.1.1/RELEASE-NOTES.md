# Release Notes

## v2.1.1 — Hosting Detection & Framework Fingerprinting

### Highlights

Added hosting provider fingerprinting (15+ providers), frontend framework detection including Alpine.js, and target reachability validation.

### What's New

- **Hosting provider detection** — Automatically identifies 15+ hosting providers from response headers and content signatures: Vercel, Netlify, Cloudflare (Pages/Workers/Proxied), Heroku, Railway, GitHub Pages, GitLab Pages, Render, Fly.io, Firebase, AWS Amplify, Azure Static Web Apps, Surge, and Glitch
- **Alpine.js detection** — Identifies Alpine.js via `x-data`, `x-init`, `x-show`, and other Alpine-specific attributes
- **Vanilla JS fallback** — When no major framework is detected, reports "Vanilla JS" instead of leaving frontend field empty
- **Target reachability validation** — Pre-scan check validates the target is reachable and responsive before starting the scan, with intelligent retry handling
- **Route extraction improvements** — Better filtering of template routes (`/:id`), filesystem paths (`/etc/`), and doc files (`.md`, `.mdx`)

### Bug Fixes

- Clarified SPA detection terminology in documentation
