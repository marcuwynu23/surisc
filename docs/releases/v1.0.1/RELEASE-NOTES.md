# Release Notes

## v1.0.1 — Pattern Expansion & Docker

### Highlights

Expanded secret detection patterns with new credential types and added Docker support for containerized scanning.

### What's New

- **Docker support** — Official Docker image published to GitHub Container Registry (`ghcr.io/marcuwynu23/surisc`)
- **Expanded secret detection** — Added patterns for additional credential types beyond the initial AWS/Stripe/GitHub set
- **Improved test coverage** — Test cases for all supported secret patterns

### Documentation

- Restructured README with clean pattern matching table and terminology section
- Added CHANGELOG for version tracking

### CI/CD

- Automated Docker image builds and publishing to GitHub Packages
