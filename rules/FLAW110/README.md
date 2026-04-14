# FLAW110 — Magic number — name it as a constant

**Severity:** info · **Tag:** hygiene · CWE-1098

## What
A numeric literal with three or more digits appears inside a comparison or arithmetic expression without being bound to a named constant. Extract it to a CONST so the value's meaning lives next to its name.

## Fix
See the rule description and the detector at `src/rules/magic_number.cr`.
