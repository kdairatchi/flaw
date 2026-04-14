# FLAW149 — Unpinned MCP/agent source

**Severity:** high · **Tag:** security · CWE-1357

## What
An MCP/agent config file references a server without a pinned version: plain `http://`, `npx` without `@<version>`, or `git+https://...` without a 40-char commit SHA. Any of these means the upstream can rotate the code your agent runs. Pin exact versions or SHAs; require HTTPS.

## Fix
See the rule description and the detector at `src/rules/unpinned_mcp_source.cr`.
