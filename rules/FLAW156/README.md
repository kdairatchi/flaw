# FLAW156 — Tool handler makes outbound request to non-literal URL

**Severity:** high · **Tag:** security · CWE-918

## What
A function registered as an agent/tool handler (e.g. `@tool`, `@mcp.tool`, or defined under `tools/` or `mcp/`) issues an outbound HTTP call with a URL derived from a variable or f-string. The model can steer the URL to any reachable host — including whitelisted domains that re-emit data. Pin URLs to a server-side allowlist before the request.

## Fix
See the rule description and the detector at `src/rules/exfil_whitelisted_domain.cr`.
