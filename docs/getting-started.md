---
title: Getting started
nav_order: 2
permalink: /getting-started/
---

# Getting started
{: .no_toc }

1. TOC
{:toc}

## Install

### From source

```sh
git clone https://github.com/kdairatchi/flaw.git
cd flaw
shards build --release --no-debug --production
./bin/flaw version
```

Requires Crystal 1.19+ and `shards`. The build is a single static binary
with no runtime deps.

### Pre-built binaries

Download from the [Releases page](https://github.com/kdairatchi/flaw/releases):

- `flaw-linux-amd64`
- `flaw-linux-arm64`
- `flaw-macos-arm64`

Checksums (SHA-256) ship alongside each release.

### Homebrew *(coming with v0.1.0 release)*

```sh
brew install kdairatchi/tap/flaw
```

## Your first scan

```sh
# Scan the current directory, pretty output
flaw scan .

# Scan a subdirectory, emit JSON for pipelines
flaw scan src/ --format json > flaw.json

# Fail the run if any high+ finding is present
flaw scan . --fail-on high
```

flaw recurses any directory of `.cr` files, automatically skipping
`lib/` and `spec/`. Override with `exclude:` in `.flaw.yml`.

## Incremental scans

Only scan files — or lines — changed since a git ref:

```sh
flaw scan . --since HEAD~1              # files changed since HEAD~1
flaw scan . --since main --since-lines  # lines added/changed since main
```

This is the best mode for PR checks: it keeps the runtime flat even on
large repos and keeps findings focused on code the PR actually touched.

## Baselines

When adopting flaw on an existing codebase, the first run will surface
every pre-existing issue. Record them as a baseline so future scans
only gate on new findings:

```sh
flaw baseline                                 # writes .flaw-baseline.json
flaw scan --baseline .flaw-baseline.json      # suppress anything already recorded
```

Commit `.flaw-baseline.json` into the repo. As bugs are fixed, the
baseline shrinks — never the other way around.

## Configuration

Drop a `.flaw.yml` at the repo root. `flaw init config` writes a stub.

```yaml
version: 1

exclude:
  - spec/
  - lib/
  - vendor/

rules:
  FLAW001:
    severity: critical
  FLAW002:
    ignore:
      - "examples/fake-keys.cr"
  FLAW005:
    disabled: true
```

Per-rule overrides:

- `severity:` — bump or drop the default severity.
- `disabled:` — turn the rule off entirely.
- `ignore:` — list of glob patterns the rule won't fire on.

## Interactive triage

```sh
flaw browse src/                # fzf-powered picker with bat preview
flaw browse --tmux popup src/   # open in a tmux popup overlay
```

Requires `fzf` and `bat` on the path. Override with `FLAW_PICKER`,
`FLAW_PREVIEW`, `FLAW_EDITOR` env vars.

## CI gate

Add this to any CI pipeline — same command on every platform:

```sh
flaw scan . --fail-on high --format sarif > flaw.sarif
```

For GitHub Actions, the one-liner becomes a full workflow — see
[CI integration](ci-integration).

## What next

- [CLI reference](cli) — every subcommand, flag, and env var.
- [Rules](rules) — the full catalog with severity pills.
- [CI integration](ci-integration) — GitHub Actions + SARIF upload.
- [Writing a rule](authoring) — scaffold + detector + fixtures +
  `lint-rules` contract.
