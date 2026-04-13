# Changelog

## [0.1.0] — unreleased

Initial release.

- CLI: `scan`, `rules`, `init`, `version`, `help`
- Eight rules: `FLAW001` command-injection, `FLAW002` hardcoded-secret, `FLAW003` sql-string-build, `FLAW004` weak-random, `FLAW005` unsafe-yaml-load, `FLAW006` path-traversal, `FLAW007` open-redirect, `FLAW008` unsafe-deserialize
- `rules/` directory as single source of truth (detector + fixtures + docs per rule)
- `flaw init rule FLAWNNN slug` scaffolds a new rule folder and detector stub
- Output formats: pretty, json, sarif (2.1.0)
- `.flaw.yml` config with per-rule severity, ignore globs, disabled flag
- `--fail-on` threshold for CI gating
- GitHub Action
