# FLAW112 — Dynamic code execution sink

**Severity:** high · **Tag:** security · CWE-94

## What
eval/exec/Function and similar sinks turn strings into executable code. If any byte of that string is attacker-influenced, it becomes RCE. Use explicit parsing, whitelists, or language-native dispatch instead.

## Fix
See the rule description and the detector at `src/rules/dangerous_eval.cr`.
