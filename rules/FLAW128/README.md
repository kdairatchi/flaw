# FLAW128 — Click handler on non-interactive element

**Severity:** low · **Tag:** a11y · CWE-1390

## What
A click handler is attached to a <div>, <span>, or similar non- interactive element without a keyboard equivalent. Keyboard users can't reach or activate the control. Use a <button>, or add both role="button" and a tabindex plus a keydown handler. WCAG 2.1.1.

## Fix
See the rule description and the detector at `src/rules/click_non_interactive.cr`.
