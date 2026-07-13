# Release Notes

## v2.2.0 — Documentation Site, Source Map Ingestion & API Recon

### Highlights

Major release adding a full documentation website, source map ingestion for deep secret discovery, Firebase/Supabase config leak detection, OpenAPI/Swagger spec discovery, and GraphQL introspection testing.

### What's New

#### Secret Detection

- **Source map ingestion** — When SuriSC finds `sourceMappingURL` references, it automatically fetches the `.map` file, parses the original source content, and recursively scans those sources for secrets. One minified bundle can reveal dozens of original source files.
- **Firebase config leak detection** — Detects `firebaseConfig` objects and `firebase.initializeApp()` calls containing exposed `apiKey` values in client-side bundles
- **Supabase config leak detection** — Detects `supabaseUrl` and `supabaseKey` variable assignments that leak Supabase project credentials
- **Cloudflare credential detection** — New patterns for exposed Cloudflare global API keys and API tokens
- **User API token detection** — Generic token assignment detection with entropy validation to filter false positives

#### Security Profiling (`-i` mode)

- **OpenAPI/Swagger spec discovery** — Probes 10 common API spec paths (`/swagger.json`, `/openapi.json`, `/api/docs`, etc.) and validates responses for `swagger`/`openapi` keys. Also scans JS bundles for Swagger/OpenAPI version references and Swagger UI tooling.
- **GraphQL introspection detection** — Sends `{ __schema { types { name } } }` introspection queries to common GraphQL endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`, `/graph`) and reports whether introspection is enabled or disabled
- **Attack surface probing expanded** — Now includes cookie security analysis and JWT indicator detection for probed endpoints

#### Documentation Website

- **Full HTML documentation site** — New pages: About, Features, Installation, Usage — with responsive design, mobile navigation, and canvas background
- **User guide** — Comprehensive markdown guide covering installation, commands, concepts, troubleshooting, FAQ, CI/CD integration, and workflows
- **Improved README** — Updated with feature comparisons, expanded use cases, architecture diagram, and CI/CD integration examples
- **Security policy** — Added `SECURITY.md` with vulnerability reporting guidelines
- **Contribution guidelines** — Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and PR template

#### Engine Improvements

- **Target reachability** — Now handles 5xx server errors gracefully during pre-scan validation
- **False positive suppression** — Route validation against SPA fallback signatures; Bitcoin address filtering; placeholder value suppression
- **Deduplication** — Improved leak deduplication by type + source URL + snippet
- **Gravity scoring** — Adjusted scoring for better prioritization (entropy-based scaling for bearer tokens and high-entropy secrets)

### Bug Fixes

- Fixed installation link consistency across documentation
- Clarified SPA detection terminology in README
- Improved informative scope handling for tech detection
- Better HTML fallback detection for `robots.txt` and `sitemap.xml` edge cases

### Maintenance

- Bumped `github.com/antchfx/xpath` dependency
- Go module updates
- CHANGELOG updates
- `.gitignore` refinements
- Test fixture improvements for dynamic payloads
