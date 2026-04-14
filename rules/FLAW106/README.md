# FLAW106 — Raw color literal outside token file

**Severity:** low · **Tag:** design · CWE-1078

## What
A 3/6/8-digit hex color or rgb()/rgba() call appears in source outside of a declared design-token file. Palette drift produces a codebase with dozens of "almost the same" shades. Move the color into the token set (tokens.css, theme.ts, tailwind.config) and reference it by name.

## Fix
See the rule description and the detector at `src/rules/color_drift.cr`.
