# Release Notes

## v1.1.1 — Technology Fingerprinting & Installers

### Highlights

Added technology stack fingerprinting, NSIS Windows installer, Debian package support, and expanded CI/CD.

### What's New

- **Technology stack detection** — Identifies frontend frameworks, HTTP version, and server technology from response headers and page content
- **NSIS Windows installer** — Native Windows setup executable for easier distribution
- **Debian package** — `.deb` package for Ubuntu/Debian Linux users
- **Secret detection expansion** — Web content scanner now detects a wider range of secrets using regex and entropy analysis
- **GitHub Actions test workflow** — Automated test runs on every push

### Maintenance

- Updated Go module dependencies
- Makefile improvements for installer and package builds
- CHANGELOG updated
