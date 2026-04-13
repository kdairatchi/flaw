# Changelog

## [0.1.0] — unreleased

Initial release.

### Rules (13 total)

**Security (`FLAW0xx`)** — 10 rules
- `FLAW001` command-injection, `FLAW002` hardcoded-secret, `FLAW003` sql-string-build
- `FLAW004` weak-random, `FLAW005` unsafe-yaml-load
- `FLAW006` path-traversal, `FLAW007` open-redirect, `FLAW008` unsafe-deserialize
- `FLAW009` weak-hash, `FLAW010` tls-verify-disabled

**AI-slop (`FLAW1xx`)** — 3 rules (novel: no other linter does this)
- `FLAW100` explanatory-comment, `FLAW101` ai-assistant-leak, `FLAW102` placeholder-value

### Commands
- `flaw scan` — pretty / json / sarif output, `--fail-on` threshold
- `flaw rules [ID]` — catalog grouped by tag, or rule detail
- `flaw lint-rules` — validates rules/ contract: folder names, rule.yml schema, detector existence, bad/good behaviour
- `flaw init config` — drop `.flaw.yml` stub
- `flaw init rule FLAWNNN slug` — scaffold rule folder + detector
- `flaw version`, `flaw help`

### Infrastructure
- `rules/` directory as single source of truth (detector + fixtures + docs per rule)
- `.flaw.yml` config with per-rule severity, ignore globs, disabled flag
- Reusable GitHub Action at `action.yml`
- CI: `lint-rules` gate + every bad.cr fires + every good.cr clean + dogfood scan
