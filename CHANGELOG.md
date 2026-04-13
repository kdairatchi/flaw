# Changelog

## [0.1.0] — 2026-04-12

Initial release.

### Rules (30 total)

**Security (`FLAW0xx`)** — 24 rules
- Injection: `FLAW001` command-injection (AST, taint-aware), `FLAW003` sql-string-build (AST), `FLAW014` xml-external-entity
- Secrets & logging: `FLAW002` hardcoded-secret (entropy-gated), `FLAW018` secret-in-log
- Crypto: `FLAW004` weak-random, `FLAW009` weak-hash, `FLAW010` tls-verify-disabled, `FLAW012` non-constant-time-compare, `FLAW016` weak-tls-version, `FLAW020` ecb-mode, `FLAW021` hardcoded-iv, `FLAW023` jwt-alg-none
- Access control & auth: `FLAW006` path-traversal, `FLAW015` mass-assignment, `FLAW019` insecure-cookie, `FLAW022` zip-slip
- Web surface: `FLAW007` open-redirect, `FLAW011` ssrf-user-url, `FLAW024` cors-wildcard-credentials
- Serialization & fs: `FLAW005` unsafe-yaml-load, `FLAW008` unsafe-deserialize, `FLAW013` insecure-tempfile
- DoS: `FLAW017` regex-redos

**AI-slop (`FLAW1xx`)** — 6 rules (novel: no other linter does this)
- `FLAW100` explanatory-comment, `FLAW101` ai-assistant-leak, `FLAW102` placeholder-value
- `FLAW103` unfinished-stub, `FLAW104` swallowed-rescue, `FLAW105` commented-auth

### Engine
- Hybrid substrate: regex-first per-line with heredoc masking + UTF-8 safe reads; per-rule AST backend via `Crystal::Parser` (FLAW001, FLAW003 migrated)
- `AstBackend` parses each file once, dispatches all `AstRule` subclasses through a shared `Crystal::Visitor`
- Intraprocedural local-binding taint: `Analysis::BindingCollector` → `Taint.current_bindings` resolves `Var → last RHS` (depth 3), kills obvious false positives
- `Taint` sanitizer recognizer: known-safe receivers (URI/HTML/JSON/Base64/Crypto::Subtle), coercion calls, constant-time compare

### Commands
- `flaw scan` — pretty / json / sarif output, `--fail-on` threshold
- `flaw rules [ID]` — catalog grouped by tag, or rule detail
- `flaw lint-rules` — validates rules/ contract: folder names, rule.yml schema, detector existence, bad/good/fp behaviour
- `flaw baseline --out FILE` + `flaw scan --baseline FILE` — suppress existing findings by `(rule_id, file, snippet)`
- `flaw doctor` — audits folder ↔ detector ↔ README ↔ config consistency
- `flaw init config` — drop `.flaw.yml` stub
- `flaw init rule FLAWNNN slug` — scaffold rule folder + detector
- `flaw version`, `flaw help`

### Infrastructure
- `rules/` directory as single source of truth (detector + `bad.cr` + `good.cr` + `fp.cr` + `README.md` per rule)
- Inline suppressions: `# flaw:ignore FLAW001`, `ignore-next`, `ignore-file`, special ID `ALL`
- Tags (`security`, `ai-slop`) with `--include-tag` / `--exclude-tag`
- `.flaw.yml` config with per-rule severity, ignore globs, disabled flag
- SARIF 2.1.0 output with CWE + OWASP `tags` and `security-severity` properties for GitHub Code Scanning
- Reusable GitHub Action at `action.yml`
- CI: `lint-rules` gate + every bad.cr fires + every good.cr + fp.cr clean + dogfood scan
- Release workflow: prebuilt binaries for linux-amd64, linux-arm64, macos-arm64 on `v*` tags
- Optional regex-only build: `shards build -Dflaw_no_ast` skips `Crystal::Parser` dependency
