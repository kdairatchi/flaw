# FLAW145 — Unsafe github.event expression in workflow

**Severity:** high · **Tag:** security · CWE-78

## What
GitHub Actions evaluates `${{ ... }}` expressions by splicing their string value directly into the shell command. If the value comes from attacker-controlled fields (issue title, PR body, comment, review, branch name), shell metacharacters inside it execute on the runner. Pass the expression through an `env:` block and reference it as an environment variable instead.

## Fix
See the rule description and the detector at `src/rules/workflow_script_injection.cr`.
