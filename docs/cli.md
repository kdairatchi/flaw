---
title: CLI reference
nav_order: 3
permalink: /cli/
---

# CLI reference
{: .no_toc }

Every subcommand supports `-h` / `--help`.

1. TOC
{:toc}

## `scan`

Analyze code and emit findings.

```sh
flaw scan [options] [path...]
```

Paths default to `.` if omitted.

| Flag | Description |
|---|---|
| `--format FORMAT` | Output format: `pretty` (default), `json`, `sarif` |
| `--fail-on LEVEL` | Fail the run if any finding at or above `info`/`low`/`medium`/`high`/`critical` |
| `--config FILE` | Config file path (default `.flaw.yml`) |
| `--baseline FILE` | Suppress findings listed in the baseline |
| `--since REF` | Only report on files changed since a git ref (e.g. `HEAD~1`, `main`) |
| `--since-lines` | With `--since`, only report findings on added/changed lines |
| `--include-tag TAG` | Only run rules with this tag (repeatable) |
| `--exclude-tag TAG` | Skip rules with this tag (repeatable) |
| `--fix` | Apply safe autofixes in place (e.g. weak-hash → strong-hash) |
| `--verify-secrets` | Probe provider APIs (AWS, GitHub) on FLAW002 candidates |
| `-v, --verbose` | Per-path progress, rule count, timing |
| `-q, --quiet` | Suppress the summary footer |
| `--no-banner` | Suppress the banner header |
| `--no-color` | Disable ANSI colors (or set `NO_COLOR`/`FLAW_NO_COLOR`) |

## `browse`

Interactive TUI picker over scan results. Requires `fzf` + `bat`.

```sh
flaw browse [--tmux popup] [path...]
```

| Env var | Effect |
|---|---|
| `FLAW_PICKER` | Override the picker binary (default `fzf`) |
| `FLAW_PREVIEW` | Override the preview tool (default `bat`) |
| `FLAW_EDITOR` | Editor launched on Enter (default `$EDITOR`, then `micro`) |

## `baseline`

Snapshot current findings so future `scan --baseline` calls ignore them.

```sh
flaw baseline [--out FILE] [--config FILE] [path...]
```

Writes `.flaw-baseline.json` by default. Commit this file into the repo
and shrink it as bugs are fixed.

## `audit`

Scan `shard.lock` for shards with known CVEs.

```sh
flaw audit
```

Reads the advisory database bundled with flaw. Exit 0 when clean, 1 when
advisories match installed shards.

## `rules`

List built-in rules or inspect one.

```sh
flaw rules               # list all rules, grouped by tag
flaw rules FLAW001       # show the title, severity, and description for a rule
```

## `lint-rules`

Validate every rule directory's contract — regex, metadata, and
`bad.cr`/`good.cr` behavior. Run this in CI as the gatekeeper for rule
contributions.

```sh
flaw lint-rules [rules_dir]
```

Exits non-zero if any rule folder is malformed, missing files, or drifts
from its fixtures.

## `doctor`

Diagnose the environment. Reports Crystal version, `CRYSTAL_PATH`, AST
backend status, rule count, and any config issues.

```sh
flaw doctor
```

Run this when rules are silently skipped or when the AST-aware rules
(FLAW001, FLAW003, etc.) don't trigger on known-bad code.

## `init`

Scaffold a config file or a new rule directory.

```sh
flaw init config [PATH]          # writes .flaw.yml (default .flaw.yml)
flaw init rule FLAWNNN slug      # scaffolds rules/FLAWNNN/ + src/rules/<slug>.cr
```

Example:

```sh
flaw init rule FLAW200 unsafe_exec
# creates: rules/FLAW200/{rule.yml,bad.cr,good.cr,README.md}
# creates: src/rules/unsafe_exec.cr
```

Implement the detector, fill the fixtures, run `flaw lint-rules`, open a
PR. See [Writing a rule](authoring).

## `regex`

Author and test rule regexes with live-feedback colorization.

```sh
flaw regex test '(?i)secret' input.cr
flaw regex cheatsheet
```

## `version` / `banner` / `help`

- `flaw version` — print the version string.
- `flaw banner` — print the branded banner.
- `flaw help` — show the top-level help.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on` |
| `1` | Finding at or above `--fail-on` (CI gate) |
| `2` | Bad CLI usage or invalid option |

## Environment variables

| Variable | Effect |
|---|---|
| `NO_COLOR` | Disable ANSI colors across all subcommands |
| `FLAW_NO_COLOR` | Same, flaw-specific |
| `CRYSTAL_PATH` | Include compiler src for AST-aware rules |
| `FLAW_PICKER` | Browse: override picker binary (default `fzf`) |
| `FLAW_PREVIEW` | Browse: override preview binary (default `bat`) |
| `FLAW_EDITOR` | Browse: override editor (default `$EDITOR` → `micro`) |
