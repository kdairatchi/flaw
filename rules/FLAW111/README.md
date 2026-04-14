# FLAW111 — Mixed CSS units within property family

**Severity:** low · **Tag:** design · CWE-1078

## What
A single stylesheet/component file mixes more than one unit (px/rem/em) within the same property family (spacing: margin/padding/gap, or sizing: width/height/font-size). Standardise on one unit per family so the scale is legible.

## Fix
See the rule description and the detector at `src/rules/unit_drift.cr`.
