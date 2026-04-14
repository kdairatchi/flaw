# FLAW142 — Obfuscated code execution chain

**Severity:** high · **Tag:** security · CWE-506

## What
Chains like `IEX([Convert]::FromBase64String(...))` or `[Reflection.Assembly]::Load(...)` are the canonical PowerShell dropper pattern. Source shipping these is either red-team tooling or a backdoor.

## Fix
See the rule description and the detector at `src/rules/obfuscated_invoke.cr`.
