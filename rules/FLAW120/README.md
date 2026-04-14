# FLAW120 — Positive tabindex breaks tab order

**Severity:** low · **Tag:** a11y · CWE-1390

## What
A tabindex greater than 0 forces this element out of natural DOM order in keyboard navigation, breaking focus flow for screen-reader users. Use tabindex="0" (focusable in order) or tabindex="-1" (programmatic focus only). WCAG 2.4.3 Focus Order.

## Fix
See the rule description and the detector at `src/rules/positive_tabindex.cr`.
