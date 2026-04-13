<div align="center">
  <img alt="flaw logo" src="docs/static/flaw-wide.webp" width="500px;">
  <p>A fast static analysis tool for finding security flaws in Crystal code.</p>
</div>

<p align="center">
<a href="https://github.com/kdairatchi/flaw/blob/main/CONTRIBUTING.md">
<img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=black"></a>
<a href="https://github.com/kdairatchi/flaw/releases">
<img src="https://img.shields.io/github/v/release/kdairatchi/flaw?style=for-the-badge&color=black&labelColor=black&logo=web"></a>
<a href="https://crystal-lang.org">
<img src="https://img.shields.io/badge/Crystal-000000?style=for-the-badge&logo=crystal&logoColor=white"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#github-action">GitHub Action</a> •
  <a href="#rules">Rules</a> •
  <a href="#contributing">Contributing</a> •
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

flaw reads your Crystal source and holds it up to the light. Each rule looks for a specific security flaw — hardcoded secrets, command injection sinks, SQL built from interpolation, weak randomness used for tokens, untrusted YAML loads. Findings print with file and line, and can be emitted as JSON or SARIF for CI and GitHub Code Scanning.

<details>
<summary><strong>Features</strong></summary>

### Scanning
- Five built-in rules covering the common high-impact Crystal footguns
- Per-rule severity override and path ignore via `.flaw.yml`
- Fail-on threshold for CI gating (`--fail-on high`)
- Recurses any directory of `.cr` files, skips `lib/` and `spec/` by default

### Output
- Pretty (colored, grouped by file, with snippet)
- JSON for pipelines and agents
- SARIF 2.1.0 for GitHub Code Scanning upload

### Integration
- Single static binary, zero runtime dependencies
- Reusable GitHub Action (`uses: kdairatchi/flaw@v0.1.0`)
- Non-zero exit on finding-at-threshold

</details>

## Installation

### From source

```bash
git clone https://github.com/kdairatchi/flaw.git
cd flaw
shards build --release --no-debug --production
./bin/flaw version
```

### Homebrew *(coming with v0.1.0 release)*

```bash
brew install kdairatchi/tap/flaw
```

### Pre-built binaries

Download from the [Releases page](https://github.com/kdairatchi/flaw/releases) — `linux-amd64`, `linux-arm64`, `macos-arm64`.

## Quickstart

```bash
flaw scan .                        # scan current directory, pretty output
flaw scan src/ --format json       # JSON for agents / pipelines
flaw scan . --format sarif > flaw.sarif
flaw scan . --fail-on high         # CI: exit 1 if any high+ finding
flaw rules                         # list built-in rules
flaw rules FLAW001                 # show rule detail
flaw init                          # drop a .flaw.yml config stub
```

## GitHub Action

```yaml
# .github/workflows/flaw.yml
name: flaw
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kdairatchi/flaw@v0.1.0
        with:
          args: scan . --fail-on high --format sarif > flaw.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: flaw.sarif
```

## Rules

| ID | Severity | Flaw |
|---|---|---|
| [`FLAW001`](rules/FLAW001/README.md) | critical | Command built from string interpolation |
| [`FLAW002`](rules/FLAW002/README.md) | high     | Hardcoded secret literal |
| [`FLAW003`](rules/FLAW003/README.md) | high     | SQL built via interpolation or concatenation |
| [`FLAW004`](rules/FLAW004/README.md) | high     | Weak RNG used near security-sensitive identifier |
| [`FLAW005`](rules/FLAW005/README.md) | medium   | YAML parsed from untrusted input |
| [`FLAW006`](rules/FLAW006/README.md) | high     | File access with user-controlled path |
| [`FLAW007`](rules/FLAW007/README.md) | medium   | Redirect to user-supplied URL without allowlist |
| [`FLAW008`](rules/FLAW008/README.md) | high     | Deserialization of untrusted data |

Every rule lives in its own folder under [`rules/`](rules/) with the detector, a vulnerable fixture (`bad.cr`), a fixed version (`good.cr`), metadata (`rule.yml`), and docs. Add one with `flaw init rule FLAW009 my-rule`.

## Configuration

`.flaw.yml` in your repo root:

```yaml
version: 1
exclude:
  - spec/
  - lib/
  - vendor/
rules:
  FLAW002:
    ignore:
      - "examples/fake-keys.cr"
  FLAW004:
    severity: critical
  FLAW005:
    disabled: true
```

## Roadmap

- **v0.2** — 10 more rules, `--fix` autofix for trivial cases, better SARIF provenance
- **v0.3** — LSP server (real-time flaws in your editor)
- **v0.4** — Baseline file (gate only on new findings)
- **v0.5** — Custom rule DSL (community rules in YAML)
- **v0.6** — Cross-file taint tracking (sources → sinks)
- **v1.0** — Plugin system, hosted rule docs at `flaw.prowlrbot.com`, Caido integration

## Contributing

flaw is an open-source project built by one person and improved by many. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule, report a false positive, or suggest a roadmap item.

## Why "flaw"?

In gemology, a **flaw** is a fracture, inclusion, or imperfection inside a crystal — the thing a trained eye spots by catching the light right. flaw does the same for Crystal code: it holds your program up to the light and shows you the fractures before someone else does.

## License

MIT © [kdairatchi](https://github.com/kdairatchi)
