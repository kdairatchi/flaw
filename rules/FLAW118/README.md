# FLAW118 — <img> without alt attribute

**Severity:** low · **Tag:** a11y · CWE-1390

## What
An <img> or <input type="image"> element has no alt attribute. Screen readers announce the filename or skip the element. Add alt="" for decorative images or alt="description" for meaningful ones (WCAG 1.1.1).

## Fix
See the rule description and the detector at `src/rules/missing_alt.cr`.
