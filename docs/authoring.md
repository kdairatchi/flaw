---
title: Writing a rule
nav_order: 6
permalink: /authoring/
---

# Writing a rule
{: .no_toc }

1. TOC
{:toc}

## The rule contract

Every flaw rule lives in its own folder under `rules/FLAWNNN/`. The
`lint-rules` subcommand enforces that each folder contains exactly:

```
rules/FLAWNNN/
├── rule.yml    # id, title, severity, tags, owasp, cwe, detector
├── bad.cr      # vulnerable fixture — MUST fire this rule
├── good.cr     # fixed equivalent — MUST NOT fire this rule
└── README.md   # human docs: what, why, how to fix
```

If any of those drift — folder name wrong, `rule.yml` missing a field,
detector file doesn't exist, `bad.cr` fails to fire, `good.cr` fires
by mistake — `lint-rules` fails and CI blocks the PR.

## Scaffold

```sh
flaw init rule FLAW200 unsafe_exec
```

That creates:

- `rules/FLAW200/{rule.yml, bad.cr, good.cr, README.md}` — filled with
  TODO-style stubs.
- `src/rules/unsafe_exec.cr` — a detector class that auto-registers via
  `Rule.inherited`.

## Implement the detector

Open `src/rules/unsafe_exec.cr`. Every rule inherits from `Flaw::Rule`
and implements four methods:

```crystal
require "./rule"

module Flaw
  class UnsafeExec < Rule
    def id : String
      "FLAW200"
    end

    def title : String
      "Command built from a non-literal string"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-TEXT
        `Process.run` takes a command that isn't a compile-time literal.
        If any part of the command derives from input, this is command
        injection.
      TEXT
    end

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, lineno|
        if m = line.match(/Process\.run\s*\(\s*"([^"]*#\{)/)
          results << Finding.new(
            rule_id: id,
            severity: default_severity,
            file: path,
            line: lineno,
            snippet: line.strip,
            message: "Non-literal string passed to Process.run",
          )
        end
      end
      results
    end
  end
end
```

## Fill the fixtures

`bad.cr` must be code that triggers the rule:

```crystal
# FLAW200 — vulnerable fixture. MUST trigger the rule.
user_input = ARGV.first
Process.run("echo #{user_input}", shell: true)
```

`good.cr` must be code that does *not* trigger the rule:

```crystal
# FLAW200 — fixed fixture. MUST NOT trigger the rule.
user_input = ARGV.first
Process.run("echo", [user_input])
```

Keep both small and representative. `lint-rules` runs the detector
against each and checks the finding count (≥1 for `bad.cr`, 0 for
`good.cr`).

## Validate locally

```sh
flaw lint-rules
shards build && ./bin/flaw scan rules/FLAW200/bad.cr    # should fire
./bin/flaw scan rules/FLAW200/good.cr                   # should stay quiet
```

## Update docs

The rule directory's `README.md` is the authoritative per-rule doc.
Update [`rules/README.md`](https://github.com/kdairatchi/flaw/blob/main/rules/README.md)
to add the new row to the correct category table.

## Open a PR

The CI workflow runs:

1. `crystal spec` — unit tests.
2. `flaw lint-rules` — rule contract validation.
3. `flaw scan .` — dogfood the whole catalog on flaw's own source.

Keep the PR title short; the [contributing guide](https://github.com/kdairatchi/flaw/blob/main/CONTRIBUTING.md)
covers the rest.
