# AGENTS.md — surisc
> Updated: 2026-11-24 · by project-aware-agent-maker · evidence-based, re-run before trusting

## Project status

SuriSC is a Go DAST reconnaissance CLI (module `surisc`, `go.mod:1-5`) that scans live frontends for leaked secrets and audits frontend security; the CLI entrypoint is `cmd/surisc/main.go:20`, flag parsing starts at `cmd/surisc/main.go:31`, the scan engine is at `internal/scanner/scanner.go:70`, and findings models are at `internal/models/models.go:42-72`. Local quality gates pass (`make test`, `make vet`, `gofmt -l .` empty, `make coverage`, `go build ./...`, `go mod verify`), and CI runs tests, vet, format check, and coverage (`.github/workflows/test.yml:21-31`). `CHANGELOG.md:7` covers v2.3.0, `makefile:36` feeds `NSIS_VERSION` to `-DPRODUCT_VERSION`, and the CLI exit-code contract is `0/1/2` (`cmd/surisc/main.go:15-19`, `:163-167`). `ROADMAP.md` is tracked (commit `fbc544b`); `PLAN.md` is still absent.

- CI: green — the push of `d2ea72b` triggered Test, Docker, CodeQL/Push on main, and go_modules runs; all completed `success` and were watched with `gh run watch <id> --exit-status`. GitHub reported 1 moderate Dependabot alert on the default branch in the push output; its details were not inspected here.

### Findings / open questions (do not edit these files to resolve silently)

1. Resolved: gofmt drift was cleaned in `7da922b`; `gofmt -l .` is empty and CI enforces `make fmt-check` (`.github/workflows/test.yml:27`).
2. Resolved: `CHANGELOG.md:7` now covers through v2.3.0 via `auto-changelog` (commit `75eef63`).
3. Resolved: `makefile:6,9,36` now use `NSIS_VERSION` as the canonical version; `.github/workflows/release.yml:56` overrides it at release time.
4. `make all` was not executed this session (unverified on this Windows host; `makefile:19,27` use POSIX `GOOS=... GOARCH=... go build` syntax).
5. Scheduled CodeQL runs appear in `gh run list`, but no CodeQL workflow file exists under `.github/workflows/**` (only `test.yml`, `release.yml`, `package-container.yml`); their source is unverified locally.
6. Resolved by this delivery: dependabot merge `88c618f` raised `go.mod` to `go 1.25.0` (`x/net v0.55`, `x/text v0.37`) while `Dockerfile:2` and both Go workflows stayed on 1.24; Docker run `45224473806` failed at `6bd29a6` with `go.mod requires go >= 1.25.0`. `Dockerfile:2`, `.github/workflows/test.yml:19`, `.github/workflows/release.yml:25`, `README.md:288`, `CONTRIBUTING.md:13`, and this file now target 1.25; local `docker build` and all Go gates pass.

## Environment & toolchain

| Tool | Version | Evidence |
| --- | --- | --- |
| Go (installed) | go1.26.1 windows/amd64 | `go version` |
| Go (module / CI target) | 1.25.0 / 1.25.x / 1.25 | `go.mod:3`, `.github/workflows/test.yml:19`, `.github/workflows/release.yml:25` |
| gocolly/colly/v2 | v2.3.0 | `go.mod:5` |
| GNU Make | 3.81 | `make --version` |
| Docker (server) | 27.5.1 | `docker version --format '{{.Server.Version}}'` |
| GitHub CLI | 2.73.0 (authenticated as marcuwynu23, repo marcuwynu23/surisc) | `gh --version`, `gh auth status`, `gh repo view` |
| Python | unavailable (`python3 --version` resolves to a Microsoft Store stub) | `python3 --version` |

## Commands

| Purpose | Command | Verified |
| --- | --- | --- |
| install/download modules | `go mod download` | yes (earlier session, exit 0) |
| test (CI parity with `test.yml:21`) | `make test` | yes (re-run after final commit; all packages pass) |
| test (direct) | `go test ./...` | yes (re-run after final commit) |
| vet | `make vet` / `go vet ./...` | yes (re-run after final commit, exit 0) |
| format check | `make fmt-check` / `gofmt -l .` | yes (empty output) |
| coverage | `make coverage` | yes (42.1% overall; `dist/coverage.out` generated, gitignored) |
| build all packages | `go build ./...` | yes (re-run after final commit, exit 0) |
| build CLI binary | `go build -o "$env:TEMP\surisc-check.exe" cmd/surisc/main.go` | yes (earlier session, exit 0; temp output removed) |
| module integrity | `go mod verify` | yes (re-run after final commit, "all modules verified") |
| container build | `docker build -t surisc-go125-check .` (Dockerfile builder) | yes (exit 0 with `golang:1.25-alpine`; image `surisc-go125-check` created locally) |

## Testing & loop engineering (mandatory)

- **Verified commands only:** treat the table above as the complete set of gates proven this session; re-run a gate before relying on it in a later session. Never mark a command verified from memory.
- **Test gates:** run `make test` (full `go test ./...` suite) before the first change and after every change, plus `go vet ./...`, a gofmt check (`gofmt -l .` must be empty for touched files), and `go build ./...`; a failing test, a skipped test without a written reason, or a failing vet/build gate blocks completion. `tests/scanner_test.go:17` is the mock-server integration test and `internal/scanner/*_test.go` hold unit tests — both are part of the full suite, not optional subsets.
- **Loop engineering:** Plan → Execute → Verify → Correct → Stop. Never declare success on the first pass; each correction re-enters the loop with the full gate set.
- **Regression:** finish every task by re-running the full suite (`make test`), not only tests around touched code; record actual output.
- **CI parity:** local `make test`, `make vet`, `make fmt-check`, and `make coverage` match `.github/workflows/test.yml:21-31` (Go 1.25.x, push/PR to main). Release builds use `go build -o ... cmd/surisc/main.go` (`.github/workflows/release.yml:53,71,77`); container builds are also verified locally with `docker build -t surisc-go125-check .`. If local and CI commands differ, document both rather than assuming equivalence.
- **Coverage/flaky policy:** `CONTRIBUTING.md:126-132` requires tests for new features, aims for >80% coverage on new code, and records a baseline (42.1% overall, `cmd/surisc` 23.0%, `internal/scanner` 44.8% at `CONTRIBUTING.md:130`); no CI threshold is enforced and no flaky-test policy is defined anywhere verified. Never silently lower the aim, never skip a flaky test, and report flakes with the command and output for a human decision.
- **Git delivery:** no implicit commit/push. Present a per-file plan with conventional messages, wait for explicit confirmation, stage only planned files, push, then watch triggered runs (`gh run watch <id> --exit-status`, `gh run view <id>`) to `success`; with no Actions, verify the remote ref with `git ls-remote origin refs/heads/<branch>` equal to local `HEAD`.
- **Tracker hygiene:** when starting an item tracked in Project Surisc #19, set its Status to `In progress` (`47fc9ee4`) with `gh project item-edit --id <item-id> --project-id PVT_kwHOA7B5Z84BSPZy --field-id PVTSSF_lAHOA7B5Z84BSPZyzg_1VhQ --single-select-option-id 47fc9ee4`; when done, set Status to `Done` (`98236657`), add an evidence comment to the linked issue with `gh issue comment`, and verify with `gh project item-list 19 --owner marcuwynu23 --format json` and `gh issue view <n> --json state,stateReason`. Moving an item to `Done` auto-closes linked issues; do not assume a comment was posted by that transition, and use `gh issue close <n> --reason completed --comment ...` only if it is still open.

## Conventions

- Go naming and layout: `camelCase` unexported / `PascalCase` exported, `snake_case.go` filenames, `*_test.go` beside code or under `tests/` (`CONTRIBUTING.md:96-100`).
- Imports grouped standard library → third-party → internal (`CONTRIBUTING.md:102-105`); `gofmt -l .` must be empty and CI enforces `make fmt-check` (`.github/workflows/test.yml:27`).
- Return and wrap errors (`fmt.Errorf("context: %w", err)`); no panics except in `main()`; logging in the scanner only (`CONTRIBUTING.md:107-111`). Shared state in goroutines is guarded with `sync.Mutex` (`internal/scanner/scanner.go:98-106`, `CONTRIBUTING.md:118-122`).
- Conventional Commits `<type>(<scope>): <description>` with scope such as `scanner`, `cli`, `models`, `docker`, `release`, `docs` (`CONTRIBUTING.md:181-222`), matching `feat`/`fix`/`docs`/`test`/`ci` history (`git log --oneline -10`).
- Test fixtures are constructed from fragments, never literal secret values (`CONTRIBUTING.md:173-179`, `tests/scanner_test.go:22-46`).
- Build artifacts belong in `dist/` and `*.exe`, both gitignored (`.gitignore:1-2`); release notes are generated under `docs/releases/` per `.git-rndocs.yaml:18-21`.
- PR checklist requires builds, tests, vet/gofmt, coverage, conventional commits, updated docs (`.github/PULL_REQUEST_TEMPLATE.md:16-24`).

## Planning documents (reference only — do not rewrite)

- `README.md` — product context, CLI reference, development commands (`README.md:11-16`, `README.md:280-320`).
- `USER-GUIDE.md` — detailed behavior and troubleshooting reference (`USER-GUIDE.md:1-14`).
- `CONTRIBUTING.md` — coding standards, testing, commit and release conventions (`CONTRIBUTING.md:94-128`, `CONTRIBUTING.md:181-283`).
- `SECURITY.md` — supported versions, responsible disclosure, safe scanning rules (`SECURITY.md:3-49`).
- `CODE_OF_CONDUCT.md`, `.github/PULL_REQUEST_TEMPLATE.md`, `.git-rndocs.yaml` — community, PR, and release-note conventions.
- `CHANGELOG.md`, `docs/releases/**` — historical release notes; `CHANGELOG.md:7` now covers through v2.3.0.
- `ROADMAP.md` — tracked ranked queue and board mapping (`ROADMAP.md:1`, commit `fbc544b`); `PLAN.md` is absent, so do not invent it. Reference the roadmap instead of duplicating its content.

## Known priorities (from gh issues)

- None open: issues #6-#9 were closed as completed on 2026-11-24 after their project items were moved to `Done`; issues #1-#3 are earlier closed history. Re-run `gh issue list --state open --limit 50 --json number,title,labels,milestone,updatedAt` before relying on this.

## Verification loop

1. **Plan** — state the intended change and the gates that will prove it correct; check this file's evidence against current files/commands first.
2. **Execute** — make only the planned changes; derive every claim from real file, command, `gh`, or manifest output.
3. **Verify** — run `make test`, `go vet ./...`, `gofmt -l .`, `go build ./...`, and any CI-parity build; read actual output.
4. **Correct** — fix every failed gate, including gofmt drift in touched files, then re-run the entire loop.
5. **Stop condition** — full suite and all gates green with output recorded, final regression done, working tree clean, planned commits pushed, every triggered run concluded `success` (or no CI plus an `ls-remote` match), and every tracked item moved to `Done` with its issue closed/commented and verified via `gh`. Otherwise report exactly what remains pending or failed.

## Never do

- Commit real secrets or literal credential fixtures; use constructed strings (`CONTRIBUTING.md:118-121,173-179`).
- Scan targets without ownership or explicit permission, or launch high-frequency scans (`SECURITY.md:43-49`).
- Skip tests, lower the >80% new-code coverage aim, ignore a skipped/failing test, or claim a gate green without observed output.
- Commit `dist/`, `*.exe`, or other build artifacts (`.gitignore:1-2`).
- Edit `.github/workflows/**`, root docs, or release notes without an explicit request; reference them instead when planning work.
- Commit or push without an explicit per-file plan and user confirmation, or declare a push done while checks are pending/failed.
- Invent versions, commands, flags, paths, issue numbers, CI conclusions, or metrics; unverifiable facts stay marked `unverified`.
