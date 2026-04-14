# FLAW144 — pull_request_target + PR-head checkout

**Severity:** high · **Tag:** security · CWE-1395

## What
A workflow triggered by `pull_request_target` runs in the context of the base repository and has access to secrets and a write-scoped GITHUB_TOKEN. Checking out the untrusted PR head (via `github.event.pull_request.head.sha` or `.ref`) causes attacker code to execute with those privileges. Use `pull_request` instead, or pin to the base SHA.

## Fix
See the rule description and the detector at `src/rules/gha_unsafe_checkout.cr`.
