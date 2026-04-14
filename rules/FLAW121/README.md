# FLAW121 — Conflicting Tailwind utilities on same element

**Severity:** low · **Tag:** design · CWE-1078

## What
Multiple Tailwind utilities from the same family (display, text size, padding, margin) appear on a single element. Only one survives the cascade; the rest are dead code. Pick one intentional utility.

## Fix
See the rule description and the detector at `src/rules/tailwind_conflict.cr`.
