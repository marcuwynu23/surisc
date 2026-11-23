# AGENTS.md — surisc
> Generated: 2026-11-24 · by project-aware-agent-maker · evidence-based, re-run before trusting

## Project status

SuriSC is a Go DAST reconnaissance CLI (module `surisc`, `go.mod:1-5`) that scans live frontends for leaked secrets and audits frontend security; the CLI entrypoint is `cmd/surisc/main.go:15`, with flag parsing at `cmd/surisc/main.go:140`, the scan engine at `internal/scanner/scanner.go:70`, and findings models at `internal/models/models.go:42-72`. Local quality gates pass (`make test`, `go test ./...`, `go vet ./...`, `go build ./...`, `go mod verify`), but `gofmt -l .` reports drift: on this Windows checkout git converts LF to CRLF (`core.autocrlf=true`; `git ls-files --eol cmd/surisc/main.go` → `i/lf w/crlf`), and even LF-normalized checks still flag 5 files, e.g. import order at `cmd/surisc/main.go:4-5`, while `CONTRIBUTING.md:115` and `.github/PULL_REQUEST_TEMPLATE.md:20` require clean gofmt. Docs describe v2.3.0 (`docs/releases/v2.3.0/RELEASE-NOTES.md:3`, `README.md:11-16`), but `CHANGELOG.md:7` stops at v2.1.0, and no `PLAN.md`, `ROADMAP.md`, or pre-existing `AGENTS.md` exists in the root (verified with `Test-Path`).

- CI: green — `gh run list --limit 50 --json ...` returned only `completed`/`success` runs: Test 10, Create and publish a Docker image 11, Release 1, CodeQL 28; no failed run required diagnosis. No run was triggered or watched by this authoring session, so push-time status remains unverified until an actual push.

### Findings / open questions (do not edit these files to resolve silently)

1. Format drift: 5 of 8 Go files fail LF-normalized gofmt (e.g. `cmd/surisc/main.go:4-5`, `internal/models/models.go:26` alignment); PR checklist requires clean gofmt (`.github/PULL_REQUEST_TEMPLATE.md:20`). Ask before running `go fmt ./...` as a separate change.
2. Stale history: `CHANGELOG.md:7` ends at v2.1.0 while `docs/releases/v2.3.0/RELEASE-NOTES.md:3` and recent commits describe v2.3.0.
3. Version wiring mismatch: `makefile:6` defines `NSIS_VERSION`, `makefile:34-37` passes `-DPRODUCT_VERSION=$(VERSION)` (undefined), and `.github/workflows/release.yml:56` overrides `NSIS_VERSION` — confirm intended variable before touching installer builds.
4. `make all` was not executed this session (unverified on this Windows host; `makefile:19,27` use POSIX `GOOS=... GOARCH=... go build` syntax).
5. Scheduled CodeQL runs appear in `gh run list`, but no CodeQL workflow file exists under `.github/workflows/**` (only `test.yml`, `release.yml`, `package-container.yml`); their source is unverified locally.

## Environment & toolchain

| Tool | Version | Evidence |
| --- | --- | --- |
| Go (installed) | go1.26.1 windows/amd64 | `go version` |
| Go (module / CI target) | 1.24.0 / 1.24.x / 1.24 | `go.mod:3`, `.github/workflows/test.yml:19`, `.github/workflows/release.yml:25` |
| gocolly/colly/v2 | v2.3.0 | `go.mod:5` |
| GNU Make | 3.81 | `make --version` |
| Docker (server) | 27.5.1 | `docker version --format '{{.Server.Version}}'` |
| GitHub CLI | 2.73.0 (authenticated as marcuwynu23, repo marcuwynu23/surisc) | `gh --version`, `gh auth status`, `gh repo view` |
| Python | unavailable (`python3 --version` resolves to a Microsoft Store stub) | `python3 --version` |

## Commands

| Purpose | Command | Verified |
| --- | --- | --- |
| install/download modules | `go mod download` | yes (this session, exit 0) |
| test (CI parity with `test.yml:22`) | `make test` | yes (this session; scanner + integration packages pass) |
| test (direct) | `go test ./...` | yes (this session; `internal/scanner` 0.425s, `tests` 22.060s) |
| vet | `go vet ./...` | yes (this session, exit 0) |
| format check | `gofmt -l .` | yes (this session; reports drift — see Project status) |
| build all packages | `go build ./...` | yes (this session, exit 0) |
| build CLI binary | `go build -o "$env:TEMP\surisc-check.exe" cmd/surisc/main.go` | yes (this session, exit 0; temp output removed) |
| module integrity | `go mod verify` | yes (this session, "all modules verified") |
| container build | local equivalent of the `docker/build-push-action@v5` step in `package-container.yml:47-55` | unverified (not executed this session) |

## Testing & loop engineering (mandatory)

- **Verified commands only:** treat the table above as the complete set of gates proven this session; re-run a gate before relying on it in a later session. Never mark a command verified from memory.
- **Test gates:** run `make test` (full `go test ./...` suite) before the first change and after every change, plus `go vet ./...`, a gofmt check (`gofmt -l .` must be empty for touched files), and `go build ./...`; a failing test, a skipped test without a written reason, or a failing vet/build gate blocks completion. `tests/scanner_test.go:17` is the mock-server integration test and `internal/scanner/*_test.go` hold unit tests — both are part of the full suite, not optional subsets.
- **Loop engineering:** Plan → Execute → Verify → Correct → Stop. Never declare success on the first pass; each correction re-enters the loop with the full gate set.
- **Regression:** finish every task by re-running the full suite (`make test`), not only tests around touched code; record actual output.
- **CI parity:** local `make test` matches `.github/workflows/test.yml:21-22` (Go 1.24.x, push/PR to main). Release builds use `go build -o ... cmd/surisc/main.go` (`.github/workflows/release.yml:53,71,77`); container builds are CI-only here and unverified locally. If local and CI commands differ, document both rather than assuming equivalence.
- **Coverage/flaky policy:** `CONTRIBUTING.md:126-129` requires tests for new features and aims for >80% coverage on new code, but no CI threshold is enforced and no flaky-test policy is defined anywhere verified; never silently lower the aim, never skip a flaky test, and report flakes with the command and output for a human decision.
- **Git delivery:** no implicit commit/push. Present a per-file plan with conventional messages, wait for explicit confirmation, stage only planned files, push, then watch triggered runs (`gh run watch <id> --exit-status`, `gh run view <id>`) to `success`; with no Actions, verify the remote ref with `git ls-remote origin refs/heads/<branch>` equal to local `HEAD`.

## Conventions

- Go naming and layout: `camelCase` unexported / `PascalCase` exported, `snake_case.go` filenames, `*_test.go` beside code or under `tests/` (`CONTRIBUTING.md:96-100`).
- Imports grouped standard library → third-party → internal (`CONTRIBUTING.md:102-105`); format with gofmt before committing, accepting that current files have known drift (`CONTRIBUTING.md:113-116`).
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
- `CHANGELOG.md`, `docs/releases/**` — historical release notes; `CHANGELOG.md` is stale relative to v2.3.0 (see Finding 2).
- `PLAN.md` / `ROADMAP.md` — absent as of 2026-11-24; do not invent or create them without instruction. If added later, reference them here instead of duplicating their content.

## Known priorities (from gh issues)

- None open: `gh issue list --state open --limit 50 --json number,title,labels,milestone,updatedAt` returned `[]` on 2026-11-24; issues #1-#3 are closed and are not active priorities. No labels or milestones were available to rank.

## Verification loop

1. **Plan** — state the intended change and the gates that will prove it correct; check this file's evidence against current files/commands first.
2. **Execute** — make only the planned changes; derive every claim from real file, command, `gh`, or manifest output.
3. **Verify** — run `make test`, `go vet ./...`, `gofmt -l .`, `go build ./...`, and any CI-parity build; read actual output.
4. **Correct** — fix every failed gate, including gofmt drift in touched files, then re-run the entire loop.
5. **Stop condition** — full suite and all gates green with output recorded, final regression done, working tree clean, planned commits pushed, and every triggered run concluded `success` (or no CI plus an `ls-remote` match). Otherwise report exactly what remains pending or failed.

## Never do

- Commit real secrets or literal credential fixtures; use constructed strings (`CONTRIBUTING.md:118-121,173-179`).
- Scan targets without ownership or explicit permission, or launch high-frequency scans (`SECURITY.md:43-49`).
- Skip tests, lower the >80% new-code coverage aim, ignore a skipped/failing test, or claim a gate green without observed output.
- Commit `dist/`, `*.exe`, or other build artifacts (`.gitignore:1-2`).
- Edit `.github/workflows/**`, root docs, or release notes without an explicit request; reference them instead when planning work.
- Commit or push without an explicit per-file plan and user confirmation, or declare a push done while checks are pending/failed.
- Invent versions, commands, flags, paths, issue numbers, CI conclusions, or metrics; unverifiable facts stay marked `unverified`.
