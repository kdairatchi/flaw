---
title: CI integration
nav_order: 5
permalink: /ci-integration/
---

# CI integration
{: .no_toc }

1. TOC
{:toc}

## GitHub Actions

The simplest possible integration — one step, SARIF upload to GitHub
Code Scanning:

```yaml
# .github/workflows/flaw.yml
name: flaw
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: kdairatchi/flaw@v0.1.0
        with:
          args: scan . --fail-on high --format sarif > flaw.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: flaw.sarif
```

Findings show up in the **Security → Code scanning** tab, annotated on
PR diffs, and — with `--fail-on high` — block the merge when a new
high-severity issue lands.

## PR-only mode

For monorepos where a full scan takes minutes, use `--since` to scan
only what the PR touched:

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0                      # needed for --since
      - uses: kdairatchi/flaw@v0.1.0
        with:
          args: >-
            scan .
            --since ${{ github.event.pull_request.base.sha }}
            --since-lines
            --fail-on high
            --format sarif > flaw.sarif
```

`--since-lines` further narrows to lines that were actually added or
changed in the PR diff — if the rule fires on an unchanged line, it's
suppressed.

## Baselines for adoption

Adopting flaw on an existing codebase without wading through a sea of
pre-existing findings:

```sh
# one-time, on a clean branch
flaw baseline
git add .flaw-baseline.json && git commit -m "chore: flaw baseline"
```

Then in CI:

```yaml
      - uses: kdairatchi/flaw@v0.1.0
        with:
          args: scan . --baseline .flaw-baseline.json --fail-on high
```

New findings fail the build; baselined ones are surfaced in output but
don't gate. As existing bugs get fixed, the baseline shrinks — never the
other way around.

## GitLab CI

```yaml
flaw:
  image: crystallang/crystal:1.19
  script:
    - git clone https://github.com/kdairatchi/flaw /tmp/flaw
    - (cd /tmp/flaw && shards build --release --no-debug --production)
    - /tmp/flaw/bin/flaw scan . --fail-on high --format json > flaw.json
  artifacts:
    when: always
    paths: [flaw.json]
```

## Pre-commit

Run flaw on staged files only:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: flaw
        name: flaw
        entry: flaw scan --since HEAD --since-lines --fail-on high
        language: system
        types: [crystal]
        pass_filenames: false
```

## SARIF output fields

Each finding in SARIF maps to:

| SARIF field | Source |
|---|---|
| `ruleId` | `FLAW001`, `FLAW023`, etc. |
| `level` | `error` (high+), `warning` (medium), `note` (low/info) |
| `message.text` | Rule title + the offending snippet |
| `locations[0]` | File, line, column |
| `partialFingerprints.findingHash/v1` | Stable hash for baseline matching |

This is accepted by GitHub Code Scanning, GitLab, Sonar, and any other
tool that ingests SARIF 2.1.0.
