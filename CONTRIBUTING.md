# Contributing to SuriSC

First off, thank you for considering contributing to SuriSC. It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.24+ | Compiler and toolchain |
| Make | Any | Task runner for builds, tests |
| Git | Any | Version control |
| NSIS (makensis) | Any | Windows installer generation (optional) |
| fpm | Any | Debian package building (optional) |

## Project Structure

```
surisc/
├── cmd/surisc/                # CLI entrypoint
│   └── main.go                # Flag parsing, output formatting
├── internal/
│   ├── models/
│   │   └── models.go          # Data types: Leak, TechInsight
│   └── scanner/
│       ├── scanner.go          # Core engine: crawling, analysis, profiling
│       ├── entropy_test.go     # Unit tests: Shannon entropy
│       ├── false_positive_test.go  # Unit tests: false positive filtering
│       └── reachability_test.go    # Unit tests: target validation
├── tests/
│   └── scanner_test.go         # Integration tests with mock HTTP server
├── docs/                       # Static documentation site (HTML)
├── logo/                       # SVG logo assets
├── installer/                  # NSIS installer script
├── dist/                       # Build output (gitignored)
├── .github/workflows/          # CI/CD pipelines
├── Dockerfile                  # Container image definition
├── makefile                    # Build and test automation
├── go.mod / go.sum             # Go module dependencies
```

## Makefile Reference

| Command | Description |
|---|---|
| `make all` | Build Windows binary + NSIS installer |
| `make exe` | Build Windows binary only |
| `make linux` | Build Linux binary |
| `make installer-nsis` | Build NSIS installer (requires `exe` first) |
| `make deb` | Build Debian package (requires `linux` first and `fpm`) |
| `make test` | Run all unit and integration tests |
| `make clean` | Remove build artifacts from `dist/` |

### Examples

```bash
# Full build
make all

# Quick build (Windows only)
make exe

# Run tests
make test

# Build for Linux + package as .deb
make linux && make deb
```

## Development Workflow

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/surisc.git
   cd surisc
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feat/my-feature
   ```
4. **Write code** following the [coding standards](#coding-standards)
5. **Write tests** for your changes (see [testing](#testing))
6. **Run tests** to make sure everything passes:
   ```bash
   make test
   ```
7. **Commit** using [conventional commits](#commit-conventions)
8. **Push** your branch and open a pull request

## Coding Standards

### Naming

- **Go**: Follow standard Go conventions (`camelCase` for unexported, `PascalCase` for exported)
- **Files**: `snake_case.go`
- **Tests**: `*_test.go` in the same package or in `tests/`

### Imports

- Group: standard library → third-party → internal
- Use `goimports` to auto-format

### Errors

- Return errors, don't panic (except in `main()`)
- Wrap errors with `fmt.Errorf("context: %w", err)` for propagation
- Log with `log.Printf` only in the scanner (not in models)

### Formatting

- Run `go fmt ./...` before committing
- No line length limit, but prefer readability

### Security

- Never commit real secrets or API keys — use test fixtures with constructed strings
- Avoid logging full request/response bodies in production paths
- Use `sync.Mutex` guards for shared state in concurrent goroutines

## Testing

### Coverage Target

All new features require tests. Aim for > 80% coverage on new code.

### Patterns

**Unit tests** (`internal/scanner/*_test.go`):

```go
func TestShannonEntropy(t *testing.T) {
    entLow := shannonEntropy("password")
    if entLow > 3.0 {
        t.Errorf("Expected low entropy for 'password', got %f", entLow)
    }
}
```

**Integration tests** (`tests/scanner_test.go`):

```go
func TestRunScan(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Serve synthetic payload with token fixtures
    }))
    defer ts.Close()

    leaks, _ := scanner.RunScan(ts.URL, false)
    if len(leaks) == 0 {
        t.Fatalf("Expected leaks to be found")
    }
}
```

### Running Tests

```bash
# All tests
make test

# Package-specific
go test ./internal/scanner/...
go test ./tests/...

# Verbose
go test -v ./...
```

### Test Fixtures

Do **not** commit literal secret values. Construct them from fragments:

```go
stripeSecret := "sk" + "_live_" + "1234567890abcdefghijklmn"
```

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/) — the same format the tool itself could generate release notes from.

```
<type>(<scope>): <description>
```

### Types

| Type | Usage |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `docs` | Documentation only changes |
| `ci` | CI/CD configuration changes |
| `perf` | Performance improvement |
| `style` | Formatting, linting (no logic change) |

### Scope

The scope should be the package or area affected:

- `scanner` — Core scanning engine
- `cli` — Command-line interface
- `models` — Data types
- `docker` — Dockerfile or container config
- `release` — Release workflows
- `docs` — Documentation

### Examples

```
feat(scanner): add detection for Shopify API tokens
fix(cli): handle missing -u flag with clear error message
test(scanner): add entropy edge cases for empty strings
docs: add CI/CD integration section to README
ci(release): add macOS ARM64 build target
refactor(scanner): extract hosting detection into separate functions
```

### Breaking Changes

Append `BREAKING CHANGE:` in the footer:

```
feat(api): change output format from array to object

BREAKING CHANGE: JSON output now wraps results in a "findings" key
```

## PR Process

### Checklist

Before submitting, ensure:

```markdown
- [ ] Code builds: `make all`
- [ ] All tests pass: `make test`
- [ ] Lint with `gofmt` / `go vet`
- [ ] Tests cover new functionality
- [ ] Commit messages follow conventional commits
- [ ] Branch is up to date with main
- [ ] Documentation updated (README, USER-GUIDE, or inline comments)
```

### Review Criteria

**What gets merged:**
- Clear bug fixes with tests
- New detection patterns with test fixtures
- Performance improvements with benchmarks
- Documentation improvements

**What doesn't get merged:**
- Breaking changes without a clear migration path
- Features without tests
- Code that introduces new dependencies unnecessarily

### Merge Process

1. Maintainer reviews the PR
2. CI must pass
3. Squash merge into main with a conventional commit message

## Release Process

1. Tag the commit with a semantic version:
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```
2. CI (`release.yml`) automatically:
   - Builds Windows, macOS (Intel + ARM), and Linux binaries
   - Creates NSIS installer
   - Builds Debian package
   - Publishes a GitHub Release with all artifacts
3. CI (`package-container.yml`) automatically:
   - Builds and pushes Docker image to `ghcr.io/marcuwynu23/surisc`

## Questions?

- Open a [GitHub Discussion](https://github.com/marcuwynu23/surisc/discussions)
- File an [issue](https://github.com/marcuwynu23/surisc/issues) for bugs or feature requests
