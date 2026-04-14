# FLAW151 — User input interpolated into system/assistant role

**Severity:** high · **Tag:** security · CWE-1039

## What
A request-derived variable is interpolated into a `{"role": "system"}` or `{"role": "assistant"}` message — an OWASP LLM01 prompt-injection primitive. Treat the system prompt as a trust boundary: never concatenate user input into it, or explicitly wrap and sanitize before doing so.

## Fix
See the rule description and the detector at `src/rules/prompt_role_injection.cr`.
