# FLAW130 — Hardcoded font-family outside token file

**Severity:** low · **Tag:** design · CWE-1078

## What
A font-family declaration hardcodes a specific family name instead of referencing a CSS variable / design token. Typography drift produces inconsistent brand expression and makes theme swaps impossible. Move the family into the token set and reference via var(--font-*).

## Fix
See the rule description and the detector at `src/rules/font_family_drift.cr`.
