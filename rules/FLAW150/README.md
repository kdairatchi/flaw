# FLAW150 — Project-local config grants execution

**Severity:** high · **Tag:** security · CWE-732

## What
A `.claude/`, `.cursor/`, `.windsurfrules`, `.continuerc`, or `.vscode/settings.json` file in the repo grants exec-like perms — Bash(*) wildcard allowlist, shell `command:` values, hook scripts, or terminal automation profiles. Any dev who clones the repo and opens it runs this. Keep project-local configs declarative; require user approval for execution.

## Fix
See the rule description and the detector at `src/rules/config_grants_exec.cr`.
