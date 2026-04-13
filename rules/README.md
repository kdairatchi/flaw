# Rules

This directory is the single source of truth for every rule `flaw` ships with. Each subdirectory holds one rule, and must contain:

```
rules/FLAWNNN/
├── rule.yml    # id, title, severity, tags, owasp, references
├── bad.cr      # code that MUST fire this rule (and only this rule, ideally)
├── good.cr     # the fixed version — MUST NOT fire this rule
└── README.md   # human docs: what, why, how to fix
```

The CI runs `flaw scan rules/*/bad.cr` and expects findings. It also runs `flaw scan rules/*/good.cr` and expects zero findings above `medium`. Both must pass for the build to be green.

## Add a rule

```bash
flaw init rule FLAW009 my-new-rule
# scaffolds rules/FLAW009/ with stubs
```

Then implement the detector at `src/rules/my_new_rule.cr`, wire it into the rule registry (it auto-registers), and open a PR.

## Catalog

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
