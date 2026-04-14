# FLAW127 — <html> without lang attribute

**Severity:** low · **Tag:** a11y · CWE-1390

## What
The root <html> element has no lang attribute. Screen readers can't choose the correct pronunciation dictionary, and translation tools can't detect the page language. Add lang="en" (or appropriate BCP-47 tag). WCAG 3.1.1 Language of Page.

## Fix
See the rule description and the detector at `src/rules/html_no_lang.cr`.
