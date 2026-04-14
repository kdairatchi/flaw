# FLAW119 — Overuse of !important in stylesheet

**Severity:** info · **Tag:** design · CWE-1078

## What
This stylesheet uses !important more than five times. That usually means selectors are fighting each other — refactor specificity or restructure the cascade instead of forcing overrides.

## Fix
See the rule description and the detector at `src/rules/important_overuse.cr`.
