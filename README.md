<p align="center">
  <img alt="flaw hero" src="docs/static/flaw-hero.png" width="640">
</p>

<p align="center">
<a href="https://github.com/kdairatchi/flaw/blob/main/CONTRIBUTING.md">
<img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=black"></a>
<a href="https://github.com/kdairatchi/flaw/releases">
<img src="https://img.shields.io/github/v/release/kdairatchi/flaw?style=for-the-badge&color=black&labelColor=black&logo=web"></a>
<a href="https://crystal-lang.org">
<img src="https://img.shields.io/badge/Crystal-000000?style=for-the-badge&logo=crystal&logoColor=white"></a>
</p>

<p align="center">
  <a href="https://kdairatchi.github.io/flaw/">Docs</a> •
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
- 83 built-in rules across security, AI-slop hygiene, design tokens, and accessibility — see [`rules/`](rules/README.md)
- Per-rule severity override, path ignore, and tag include/exclude via `.flaw.yml` or CLI flags
- Incremental scans with `--since <ref>` (only report on files/lines changed since a git ref)
- Baselines (`flaw baseline` + `--baseline .flaw-baseline.json`) to gate only on new findings
- `--fix` for safe autofixes (e.g. weak-hash upgrades)
- `--verify-secrets` to probe provider APIs (AWS, GitHub) on FLAW002 matches
- Recurses any directory of `.cr` files, skips `lib/` and `spec/` by default

### Commands
- `scan`  — analyze code and emit findings
- `browse` — interactive TUI triage (fzf + bat + optional tmux popup)
- `baseline` — snapshot current findings so future scans ignore them
- `audit` — scan `shard.lock` for shards with known CVEs
- `rules` / `lint-rules` — list rules, or validate the `rules/` contract in CI
- `init config` / `init rule` — scaffold a `.flaw.yml` or a new rule folder
- `regex` / `doctor` — author rule regexes, diagnose the environment

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
flaw scan .                                      # scan current directory, pretty output
flaw scan src/ --format json                     # JSON for agents / pipelines
flaw scan . --format sarif > flaw.sarif
flaw scan . --fail-on high                       # CI: exit 1 if any high+ finding
flaw scan . --since HEAD~1 --since-lines         # only findings on lines changed since HEAD~1
flaw scan . --include-tag security               # only run rules tagged 'security'
flaw scan . --fix                                # apply safe autofixes in place
flaw scan . --verify-secrets                     # live-probe AWS/GitHub keys from FLAW002

flaw browse src/                                 # interactive TUI triage (fzf + bat)
flaw browse --tmux popup src/                    # open picker in a tmux popup

flaw baseline                                    # snapshot current findings to .flaw-baseline.json
flaw scan --baseline .flaw-baseline.json         # suppress baselined findings

flaw audit                                       # scan shard.lock for known CVEs
flaw doctor                                      # diagnose Crystal version, AST backend, config
flaw regex test '(?i)secret' input.cr            # interactively tune rule regexes

flaw rules                                       # list built-in rules, grouped by tag
flaw rules FLAW001                               # show rule detail
flaw lint-rules                                  # validate rules/ directory contract
flaw init config                                 # drop a .flaw.yml config stub
flaw init rule FLAW200 my-new-rule               # scaffold a new rule folder + detector
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

flaw ships **83 rules** split into two ID ranges. Full catalog, severity, tags, CWE, and OWASP mapping live in [`rules/README.md`](rules/README.md).

### Security (`FLAW0xx`) — 24 rules

Real vulnerabilities. Default severity is medium+; designed for `--fail-on high` in CI.

| ID | Severity | Flaw |
|---|---|---|
| [`FLAW001`](rules/FLAW001/README.md) | critical | Command built from string interpolation |
| [`FLAW002`](rules/FLAW002/README.md) | high     | Hardcoded secret literal |
| [`FLAW003`](rules/FLAW003/README.md) | high     | SQL built via interpolation or concatenation |
| [`FLAW009`](rules/FLAW009/README.md) | high     | Weak hash (MD5/SHA1) for password or integrity |
| [`FLAW011`](rules/FLAW011/README.md) | high     | Outbound HTTP to user-controlled URL (SSRF) |
| [`FLAW014`](rules/FLAW014/README.md) | high     | XML parsed without disabling external entities (XXE) |
| [`FLAW022`](rules/FLAW022/README.md) | high     | Archive entry extracted without normalization (zip-slip) |
| [`FLAW023`](rules/FLAW023/README.md) | critical | JWT with `alg:none` or verification disabled |
| [`FLAW024`](rules/FLAW024/README.md) | high     | CORS wildcard / echoed origin with credentials |
| …and 15 more | | see [`rules/README.md`](rules/README.md) |

### `FLAW1xx` — hygiene, AI-slop, supply chain, and LLM app rules — 59 rules

Novel territory: catches vibe-coded AI paste-through, LLM-app footguns (prompt-role injection, unfenced tool results, user-controlled `max_tokens`), MCP/agent supply-chain hazards, and design/a11y token drift. Groups include:

| Group | Range | Examples |
|---|---|---|
| AI-slop hygiene | `FLAW100`–`FLAW108` | narration comments, assistant boilerplate, placeholders, unfinished stubs, silenced rescues, commented-out auth |
| Design / a11y   | `FLAW106`, `FLAW109`, `FLAW111`, `FLAW118`–`FLAW121`, `FLAW127`–`FLAW131` | raw color literals, contrast fail, mixed CSS units, missing alt/lang, Tailwind conflicts |
| Security sinks  | `FLAW112`–`FLAW117`, `FLAW122`–`FLAW126`, `FLAW132`–`FLAW148` | dynamic eval, DOM XSS, SSTI, prototype pollution, Log4Shell, NoSQL injection, PII in logs, debug-in-prod, cloud-metadata, LOLBIN, insecure GitHub Actions, open security groups, source maps shipped |
| LLM / MCP       | `FLAW149`–`FLAW157` | unpinned MCP source, project-local config grants exec, role injection, tool result unfenced, user-controlled `max_tokens`, non-literal tool-handler URLs, AI-tool config committed |

Every rule lives in its own folder under [`rules/`](rules/) with the detector, a vulnerable fixture (`bad.cr`), a fixed version (`good.cr`), metadata (`rule.yml`), and docs. Add one with `flaw init rule FLAW200 my-rule`.

## Rule validator

`flaw lint-rules` enforces the rule contract — every folder matches `FLAWNNN`, has all four required files, the `rule.yml` parses and has the required keys, the detector file exists, and each `bad.cr` + `good.cr` behaves as claimed. Run it in CI as the gatekeeper for rule contributions.

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
- **v1.0** — Plugin system, hosted rule docs at [`flaw.prowlrbot.com`](https://flaw.prowlrbot.com) (landing page lives under [`docs/`](docs/) — enable GitHub Pages with `main` / `/docs`), Caido integration

## Contributing

flaw is an open-source project built by one person and improved by many. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule, report a false positive, or suggest a roadmap item.

## Why "flaw"?

In gemology, a **flaw** is a fracture, inclusion, or imperfection inside a crystal — the thing a trained eye spots by catching the light right. flaw does the same for Crystal code: it holds your program up to the light and shows you the fractures before someone else does.

## Security

Report suspected vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

MIT © [kdairatchi](https://github.com/kdairatchi)
