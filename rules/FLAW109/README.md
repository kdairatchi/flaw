# FLAW109 — Low color contrast (WCAG AA fail)

**Severity:** low · **Tag:** design · CWE-1164

## What
Foreground/background hex pair in the same CSS rule fails WCAG AA (ratio < 4.5:1 for normal text). Pick a darker foreground or lighter background so the text is legible to low-vision users.

## Fix
See the rule description and the detector at `src/rules/contrast_fail.cr`.
