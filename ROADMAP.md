# Roadmap — SuriSC

> Updated: 2026-11-24 · Sources: status audit, gh issues, comparable-project research

## Current status

SuriSC is a Go 1.24 DAST reconnaissance CLI (`go.mod:3`) that scans live frontends for leaked secrets and audits frontend security. The latest published release is v2.3.0 (`gh release list`, 2026-07-22); `README.md:11-16` and `docs/releases/v2.3.0/RELEASE-NOTES.md:3` describe that version, but `CHANGELOG.md:7` stops at v2.1.0.

Quality gates re-run on 2026-11-24: `make test`, `go test ./...`, `go vet ./...`, `go build ./...`, `go mod verify`, and `go mod download` all exited 0. `gofmt -l .` returned a non-empty list; 5 files still fail LF-normalized gofmt (e.g. `cmd/surisc/main.go:4-5`, `internal/models/models.go:26`). The last 50 Actions runs were all `completed`/`success` (`gh run list --limit 50`); no failed run exists to diagnose.

Open issues: #6-#9, created 2026-11-24 from the Bug Report/Feature Request templates (`gh issue list --state open --limit 100 --json ...`); each maps to a Now item below. Issues #1 and #2 closed 2026-03-23, #3 closed 2026-03-19; they are stale history, not active commitments. Ranks 5-7 remain `needs-issue`. Priority rubric: P0 security/data-loss/blockers · P1 production readiness · P2 core gaps vs comparable projects · P3 enhancements.

Existing GitHub Project adopted, not duplicated: `Project Surisc` #19 (`https://github.com/users/marcuwynu23/projects/19`), identified via `gh project list --owner marcuwynu23 --limit 100` and confirmed linked to `marcuwynu23/surisc` via `gh api graphql`. Issues #6-#9 were added with Status=Ready, Priority=P1, Size=S/M/M/S and verified by GraphQL field lookup; no new board was created.

## Implemented features

| Feature | Status | Evidence |
| --- | --- | --- |
| Secret-pattern detection (AWS, GCP, GitHub, Stripe, Slack, JWT, private key, generic) | implemented | `internal/scanner/scanner.go:44-63`, `:1012-1148`; `internal/scanner/scanner_test.go:14-142` |
| Response-header secret scanning with header allowlist | implemented | `internal/scanner/scanner.go:66`, `:1712-1764`; `internal/scanner/scanner_test.go:1265-1311` |
| Entropy scoring and false-positive filtering | implemented | `internal/scanner/scanner.go:1251-1288`, `:1161-1248`; `internal/scanner/scanner_test.go:1199-1263` |
| Source-map extraction and secret scanning, including `.map` fetch | implemented | `internal/scanner/scanner.go:67`, `:1827-1898`; `internal/scanner/scanner_test.go:1092-1160` |
| Route discovery, link/JS crawl, and attack-surface probe | implemented | `internal/scanner/scanner.go:68-87`, `:264-400`, `:1330-1710`; `README.md:27-36` |
| API spec and GraphQL endpoint probing | implemented | `internal/scanner/scanner.go:83-86`, `:1330-1500`; `internal/scanner/integration_test.go:11-39` |
| Frontend security audit (CSP, CORS, cookies, CSRF, clickjacking) | implemented | `internal/scanner/scanner.go:89`, `:227-236`, `:2100-2299`; `internal/scanner/helpers_test.go:1-14` |
| Client storage token and state-management fingerprinting | implemented | `internal/scanner/scanner.go:72-81`, `:1920-2010`; `internal/scanner/detection_test.go:1-14` |
| CLI flags `-u`, `-o`, `-i` with concurrent scanning | implemented | `cmd/surisc/main.go:140-152`; `internal/scanner/scanner.go:70-106`, `:228-236` |
| JSON HUD output, summary, and verbose mode | implemented | `cmd/surisc/main.go:15-138`; `internal/models/models.go:42-72` |
| Release packaging: Windows/macOS/Linux, NSIS, deb, Docker | partial | `.github/workflows/release.yml:53-77`; `.github/workflows/package-container.yml:47-55`; `makefile:6,34-37` |
| Test/vet/build quality gates | partial | `make test`, `go vet ./...`, `go build ./...` exited 0; `.github/workflows/test.yml:21-22` runs only `make test` |
| Current changelog and release notes | absent | `CHANGELOG.md:7`; `docs/releases/v2.3.0/RELEASE-NOTES.md:3`; `gh release list` |
| Coverage baseline and flaky-test policy | absent | `CONTRIBUTING.md:126-129`; no threshold in `.github/workflows/test.yml` |
| Configurable patterns, allowlist/baseline, SARIF output | absent | `internal/scanner/scanner.go:44-63`; `USER-GUIDE.md:327-329` |
| Machine-readable CI exit-code contract | absent | `cmd/surisc/main.go:15-138`; `USER-GUIDE.md:268-276` |
| Advisory-backed vulnerable-JavaScript detection | partial | `internal/scanner/scanner.go:2504-2523` |
| GitHub Projects board for this roadmap | partial | `gh project list --owner marcuwynu23 --limit 100`; `gh project view 19 --owner marcuwynu23 --format json`; `gh project field-list 19 --owner marcuwynu23 --format json` |

## Production readiness checklist

- [ ] Tests run green + coverage baseline — `make test` exited 0; `CONTRIBUTING.md:128` states a >80% aim but no baseline was observed.
- [ ] CI on every push/PR (lint, typecheck, tests) — `.github/workflows/test.yml:21-22` runs only `make test`; no vet or gofmt step.
- [ ] Error handling and logging/observability — conventions exist in `CONTRIBUTING.md:107-111`; no systematic verification was observed.
- [ ] Docs match actual behavior — `CHANGELOG.md:7` is stale; `USER-GUIDE.md:268-276` assumes an exit-code contract the CLI does not implement.
- [ ] Packaging, versioning, changelog, release process — assets exist, but `makefile:6,34-37` and `.github/workflows/release.yml:56` disagree on the NSIS version variable.
- [ ] Dependency audit / secret scanning — 28 scheduled CodeQL runs succeeded, but no CodeQL workflow file exists locally; no dependency-audit gate was observed.

## Prioritized queue (Now / Next / Later)

Effort: S (<1 day) / M (1-3 days) / L (1-2 weeks) / XL (split). Phase estimates from evidence: Now ~1-2 weeks, Next ~2-4 weeks, Later unscheduled. Rank is shown in each Item cell; rank 1 is the single next thing to build.

### Now

| Item | Priority | Issue | Effort | Status |
| --- | --- | --- | --- | --- |
| 1. Repair release version wiring and regenerate `CHANGELOG.md` through v2.3.0 | P1 | #6 | S | at risk |
| 2. Define CLI exit-code contract and document CI gating | P1 | #7 | M | at risk |
| 3. Promote vet + gofmt into CI and establish a coverage baseline | P1 | #8 | M | at risk |
| 4. Sync this ranked queue into the adopted GitHub Project board | P1 | #9 | S | on track |

Why this rank: v2.3.0 shipped with a stale changelog and an undefined `$(VERSION)` (rank 1); `USER-GUIDE.md:268-276` promises exit-code behavior absent from `cmd/surisc/main.go` (rank 2); PR gates are not enforced in CI while gofmt drift is observed (rank 3); board sync is now verified from GraphQL (rank 4).

### Next

| Item | Priority | Issue | Effort | Status |
| --- | --- | --- | --- | --- |
| 5. Config-driven detection rules with allowlist/baseline and SARIF/JSON output | P2 | needs-issue | L | planned |
| 6. Advisory-backed vulnerable-JavaScript detection with a maintained feed | P2 | needs-issue | L | planned |

Why this rank: these are core gaps versus comparable projects, not current release blockers; `USER-GUIDE.md:327-329` and `internal/scanner/scanner.go:2504-2523` are the evidence.

### Later

| Item | Priority | Issue | Effort | Status |
| --- | --- | --- | --- | --- |
| 7. Opt-in verified/live secret re-check workflow | P3 | needs-issue | XL (split) | planned |

Why this rank: replaying discovered credentials to providers needs explicit consent; this is an enhancement, not production readiness.

## Research: comparable projects

| Practice | Source | Decision |
| --- | --- | --- |
| Config-driven rules, allowlists/baseline, SARIF/JSON reporting, and exit codes — SuriSC hard-codes patterns in `internal/scanner/scanner.go:44-63` and exposes no custom-pattern flag (`USER-GUIDE.md:327-329`). | https://github.com/gitleaks/gitleaks | adapt |
| Multi-arch release assets with checksums and generated release notes — `.github/workflows/release.yml:53-77` builds 3 OS targets, NSIS, and deb, but no checksums were observed and `CHANGELOG.md:7` is stale. | https://github.com/gitleaks/gitleaks/releases | adapt |
| Written release runbook with pre/draft/publish/post steps — SuriSC has tag-triggered automation but no checked, human-owned release checklist. | https://github.com/zaproxy/zaproxy/blob/main/RELEASING.md | adopt |
| CI scanning on push/PR with non-zero exit on findings and verified-only mode — useful as a pipeline contract; repository scanning and live-target DAST have different inputs, so verification stays opt-in. | https://trufflesecurity.com/docs/scanning-in-ci | adapt |
| Advisory-backed vulnerable-JS detection, CycloneDX/SBOM output, configurable exit codes — SuriSC's `VULNERABLE_CDN_LIBRARY` needs a maintained advisory source instead of generic guidance. | https://github.com/RetireJS/retire.js/blob/master/README.md | adapt |
| Verified/live secret re-check — avoid replaying discovered credentials without consent; keep as rank 7 only. | https://trufflesecurity.com/docs/scanning-in-ci | skip |

## Risks / open questions

- GitHub Projects scope is fixed: `gh auth status` now lists `project`, and `gh project list --owner marcuwynu23 --limit 100` succeeded. The adopted board #19 has Status options Backlog/Ready/In progress/In review/Done and Priority options P0/P1/P2; it has no P3 option, and the installed `gh` CLI has no field-update subcommand. Per user decision, rank 7 Priority stays unset rather than being remapped to P2.
- Board field mapping: roadmap Effort maps to the board's existing Size field (XS/S/M/L/XL); roadmap Now maps to Status Ready. Ranks 5-7 remain `needs-issue` and are not on the board; adding them would require explicit issue-creation approval. No new fields were invented.
- Open issues #6-#9 were created from repo templates with user approval and added to board #19; no issue, label, milestone, or release content was edited.
- Rank 1 depends on deciding whether `NSIS_VERSION` or a new `VERSION` variable is canonical (`makefile:6` vs `makefile:34-37` vs `.github/workflows/release.yml:56`).
- Rank 2 changes observable CLI behavior; document exit codes and update `USER-GUIDE.md` in the same change.
- Gofmt drift needs a separate, explicit `go fmt ./...` decision; do not fold it silently into rank 3.
- `make all` is unverified on Windows because `makefile:19,27` use POSIX `GOOS=... GOARCH=...` syntax.
- Scheduled CodeQL runs exist (`gh run list`, 28 success) but no CodeQL workflow file exists under `.github/workflows/**`; source is unverified.
- Authenticated/JS-execution scanning is explicitly out of scope in `README.md:52-56`; do not add it to the queue without an explicit mandate.
