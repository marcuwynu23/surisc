# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| 1.1.x | Yes |
| < 1.1 | No |

## Reporting a Vulnerability

SuriSC scans for leaked credentials, but if you find a vulnerability **in the tool itself**, please report it responsibly.

**Do not** open a public GitHub issue. Instead, email `help@marcuwynu.space` with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fix (optional)

You can expect:

- **Acknowledgment** within 48 hours
- **Status update** within 5 business days
- **Fix timeline** once the issue is confirmed and prioritized

We believe in coordinated disclosure. Please give us reasonable time to address the issue before publicizing it.

## Scope

This security policy covers:

- The SuriSC CLI tool and its source code
- CI/CD pipeline definitions
- Docker images published to GHCR

Out of scope:

- Third-party dependencies (report those to their respective maintainers)
- Targets scanned *by* SuriSC (those are users' own security concerns)

## Safe Usage

When running SuriSC:

- Only scan targets you own or have explicit permission to test
- Avoid high-frequency scanning that could constitute a denial-of-service attack
- Review findings responsibly — a leaked key should be revoked, not exploited
