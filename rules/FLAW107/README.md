# FLAW107 — Hardcoded external URL or IP in source

**Severity:** low · **Tag:** hygiene · CWE-1188

## What
An http(s):// URL pointing at a non-local host, or a public IP literal, is embedded in source code. Move it to configuration (ENV var, settings file) so environments can diverge and endpoints can rotate without a code change.

## Fix
See the rule description and the detector at `src/rules/hardcoded_url.cr`.
