# FLAW122 — Server-side template injection

**Severity:** high · **Tag:** security · CWE-94

## What
Rendering a template from a string built with interpolation lets an attacker inject template directives that execute in the engine's sandbox — often leading to RCE. Pass untrusted data as context variables, never as part of the template source.

## Fix
See the rule description and the detector at `src/rules/ssti.cr`.
