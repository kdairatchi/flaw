---
title: Home
layout: home
nav_order: 1
description: "flaw — a fast static analysis tool for finding security flaws in Crystal code."
permalink: /
---

<div class="flaw-hero" markdown="0">
  <img class="flaw-hero-art" alt="flaw hero" src="{{ site.baseurl }}/static/flaw-hero.png">
  <img class="flaw-hero-logo" alt="flaw logo" src="{{ site.baseurl }}/static/flaw-wide.svg">
  <p class="flaw-tagline">A fast static analysis tool for finding security flaws in Crystal code.</p>
  <div class="flaw-cta">
    <a href="getting-started">Get started</a>
    <a class="ghost" href="rules">Browse rules</a>
    <a class="ghost" href="https://github.com/kdairatchi/flaw">GitHub</a>
  </div>
</div>

flaw reads your Crystal source and holds it up to the light. Each rule looks
for a specific flaw — hardcoded secrets, command-injection sinks, SQL built
from interpolation, weak randomness used for tokens, untrusted YAML loads,
LLM-app footguns. Findings print with file and line, and can be emitted as
JSON or SARIF for CI and GitHub Code Scanning.

<div class="flaw-stats" markdown="0">
  <div class="flaw-stat">
    <span class="num">83</span>
    <span class="label">rules shipped</span>
  </div>
  <div class="flaw-stat">
    <span class="num">24</span>
    <span class="label">security · FLAW0xx</span>
  </div>
  <div class="flaw-stat">
    <span class="num">59</span>
    <span class="label">hygiene · FLAW1xx</span>
  </div>
  <div class="flaw-stat">
    <span class="num">1</span>
    <span class="label">static binary</span>
  </div>
</div>

## Why flaw

Most Crystal projects either go unscanned entirely or get run through
general-purpose linters that don't know the language's footguns. flaw is
Crystal-first and opinionated:

- **Crystal-native.** Rules know about `Process.run`, `YAML.parse`,
  `DB.exec` with interpolation, `Random` vs `Random::Secure`, `OpenSSL`
  verification toggles — written by someone who ships Crystal.
- **One static binary.** `shards build --release` and you're done. No
  Python venv, no node_modules, no runtime. Ships for linux-amd64,
  linux-arm64, macos-arm64.
- **Catches AI-slop.** 6 novel rules (FLAW100–FLAW108) detect unedited
  LLM paste-through — narration comments, assistant boilerplate,
  placeholder secrets, commented-out auth checks. No other linter does
  this.
- **Covers the AI stack too.** FLAW149–FLAW157 catch LLM-app security
  bugs: unpinned MCP sources, user input injected into system prompts,
  unfenced tool results, user-controlled `max_tokens`, tool handlers
  making outbound calls to non-literal URLs.
- **CI-ready.** `--fail-on high`, `--baseline`, `--since HEAD~1
  --since-lines`, SARIF 2.1.0 for GitHub Code Scanning, a reusable
  GitHub Action, `lint-rules` as a gatekeeper for rule contributions.

## Get running in 60 seconds

```sh
# From source
git clone https://github.com/kdairatchi/flaw && cd flaw
shards build --release --no-debug --production
./bin/flaw version

# Scan your project
./bin/flaw scan path/to/your/project
```

Or grab a prebuilt static binary from
[Releases](https://github.com/kdairatchi/flaw/releases)
(`linux-amd64`, `linux-arm64`, `macos-arm64`).

{: .note }
> flaw is in v0.1 — the rule contract is stable but the CLI surface is
> still small. See the [changelog](https://github.com/kdairatchi/flaw/blob/main/CHANGELOG.md)
> for the running log and the roadmap at the bottom of this page.

## Rule catalog at a glance

<div class="flaw-cats" markdown="0">
  <div class="flaw-cat">
    <h4>Security</h4>
    <span class="range">FLAW001–FLAW024 · 24 rules</span>
    <p>Injection, secrets, crypto, auth, CORS, XXE, SSRF, zip-slip, JWT
    alg:none. Default severity medium+; designed for <code>--fail-on high</code>.</p>
  </div>
  <div class="flaw-cat">
    <h4>AI-slop hygiene</h4>
    <span class="range">FLAW100–FLAW108 · 9 rules</span>
    <p>Unedited LLM paste-through: narration comments, assistant
    boilerplate, placeholders, unfinished stubs, silenced rescues,
    commented-out auth.</p>
  </div>
  <div class="flaw-cat">
    <h4>Design &amp; a11y</h4>
    <span class="range">FLAW106, 109, 111, 118–121, 127–131 · 11 rules</span>
    <p>Raw color literals, WCAG contrast fails, mixed CSS units, missing
    <code>alt</code>/<code>lang</code>, Tailwind conflicts, positive tabindex.</p>
  </div>
  <div class="flaw-cat">
    <h4>Security sinks</h4>
    <span class="range">FLAW112–FLAW148 · 29 rules</span>
    <p>Eval, DOM XSS, SSTI, prototype pollution, Log4Shell, NoSQL
    injection, PII in logs, debug-in-prod, cloud metadata, LOLBIN,
    insecure GitHub Actions, open security groups, shipped source maps.</p>
  </div>
  <div class="flaw-cat">
    <h4>CI/CD &amp; GHA</h4>
    <span class="range">FLAW144, FLAW145 · 2 rules</span>
    <p><code>pull_request_target</code> + PR-head checkout, unsafe
    <code>github.event</code> expressions in workflows.</p>
  </div>
  <div class="flaw-cat">
    <h4>LLM / MCP</h4>
    <span class="range">FLAW149–FLAW157 · 9 rules</span>
    <p>Unpinned MCP source, project-local exec grants, prompt-role
    injection, unfenced tool results, user-controlled
    <code>max_tokens</code>, non-literal tool URLs.</p>
  </div>
</div>

Full list with severity, tags, OWASP, and CWE mapping is in the
**[rule catalog](rules)** and at
[`rules/README.md`](https://github.com/kdairatchi/flaw/blob/main/rules/README.md).

## What to read next

- **[Getting Started](getting-started)** — install paths, your first
  scan, baseline + CI wiring.
- **[CLI Reference](cli)** — every subcommand, flag, and env var.
- **[Rules](rules)** — full catalog with severity pills and grouping.
- **[CI Integration](ci-integration)** — GitHub Action, SARIF upload,
  gating on `--fail-on high`.
- **[Writing a rule](authoring)** — scaffold + contract + `lint-rules`
  validation.

## Roadmap

| Version | Theme |
|---|---|
| **v0.2** | 10 more rules, `--fix` autofix expansion, better SARIF provenance |
| **v0.3** | LSP server (real-time flaws in your editor) |
| **v0.4** | Baseline file with per-rule / per-severity gating |
| **v0.5** | Custom rule DSL (community rules in YAML) |
| **v0.6** | Cross-file taint tracking (sources → sinks) |
| **v1.0** | Plugin system, hosted rule docs at `flaw.prowlrbot.com`, Caido integration |

## License

MIT. See [LICENSE](https://github.com/kdairatchi/flaw/blob/main/LICENSE).
