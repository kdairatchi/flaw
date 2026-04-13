# Rules

This directory is the single source of truth for every rule `flaw` ships with. Each subdirectory holds one rule, and must contain:

```
rules/FLAWNNN/
├── rule.yml    # id, title, severity, tags, owasp, cwe, detector, references
├── bad.cr      # code that MUST fire this rule
├── good.cr     # the fixed version — MUST NOT fire this rule
└── README.md   # human docs: what, why, how to fix
```

`flaw lint-rules` enforces the contract. It validates every folder name, every `rule.yml` schema, every `detector` pointer, and runs each rule against its own `bad.cr` + `good.cr` — build fails if any drifts.

## Add a rule

```bash
flaw init rule FLAW011 my-new-rule
# scaffolds rules/FLAW011/ and src/rules/my_new_rule.cr
```

Implement the detector (it auto-registers via `Rule.inherited`), fill in `bad.cr` and `good.cr`, run `flaw lint-rules`, open a PR.

## Categories

**Security rules (`FLAW0xx`)** — real vulnerabilities, exit-code-1 in CI.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW001](FLAW001/README.md) | critical | injection       | Command built from string interpolation |
| [FLAW002](FLAW002/README.md) | high     | secrets         | Hardcoded secret literal |
| [FLAW003](FLAW003/README.md) | high     | injection       | SQL built via interpolation/concat |
| [FLAW004](FLAW004/README.md) | high     | crypto          | Weak RNG near security-sensitive name |
| [FLAW005](FLAW005/README.md) | medium   | deserialization | YAML parsed from untrusted input |
| [FLAW006](FLAW006/README.md) | high     | path            | Path traversal via user-controlled path |
| [FLAW007](FLAW007/README.md) | medium   | redirect        | Open redirect from user-supplied URL |
| [FLAW008](FLAW008/README.md) | high     | deserialization | Unsafe deserialization of untrusted bytes |
| [FLAW009](FLAW009/README.md) | high     | crypto          | Weak hash (MD5/SHA1) for password or integrity |
| [FLAW010](FLAW010/README.md) | high     | crypto          | TLS certificate verification disabled |

**AI-slop rules (`FLAW1xx`)** — code hygiene: detect unedited LLM paste-through. Low/medium severity, meant for `--fail-on medium` in CI after the codebase is clean.

| ID | Severity | Tag | Flaw |
|---|---|---|---|
| [FLAW100](FLAW100/README.md) | low      | ai-slop  | Explanatory narration comment ("This function does X") |
| [FLAW101](FLAW101/README.md) | medium   | ai-slop  | AI assistant boilerplate in strings or comments |
| [FLAW102](FLAW102/README.md) | medium   | ai-slop  | Placeholder value never replaced (`your-api-key-here`, `REPLACE_ME`) |
