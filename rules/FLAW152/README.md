# FLAW152 — Tool result appended to prompt without fence

**Severity:** medium · **Tag:** security · CWE-1039

## What
A `{"role": "tool"}` / `{"role": "function"}` message carries a bare variable into the conversation. Tool output is untrusted — wrap it in a delimiter (e.g. `<tool_result>…</tool_result>`) or explicitly sanitize before appending so injected instructions can't escape.

## Fix
See the rule description and the detector at `src/rules/tool_result_unfenced.cr`.
