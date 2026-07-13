# Release Notes

## v1.0.0 — Initial Release

### Highlights

Initial release of SuriSC — a memory-resident reconnaissance tool that scrapes JavaScript bundles from target URLs and detects leaked secrets before they reach production.

### What's New

- **Secret detection engine** — Scans JS bundles for AWS access keys, Stripe secret keys, GitHub personal access tokens, and Google API keys using regex pattern matching
- **Shannon entropy analysis** — Flags high-density random strings that resemble real credentials
- **CLI interface** — Simple `-u` flag for target URL scanning with human-readable output
- **Makefile build system** — Cross-platform builds for Windows, macOS, and Linux
- **GitHub CI** — Automated build and test pipeline

### Maintenance

- Project scaffolding: Go module, `.gitignore`, directory structure
- Initial test cases for secret detection patterns
- README with installation and quick-start instructions
