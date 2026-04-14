# FLAW155 — User-controlled LLM max_tokens without clamp

**Severity:** medium · **Tag:** security · CWE-770

## What
An LLM call's `max_tokens` / `maxOutputTokens` parameter is set from a request-derived variable without a numeric clamp. A single malicious request can drive per-call billing to the API's cap — wrap the value in `min(req_value, HARD_CAP)` or ignore the client-supplied field entirely.

## Fix
See the rule description and the detector at `src/rules/user_controlled_max_tokens.cr`.
