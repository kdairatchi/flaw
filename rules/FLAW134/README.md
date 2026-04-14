# FLAW134 — Debug enabled in config

**Severity:** medium · **Tag:** security · CWE-489

## What
Framework debug modes leak stack traces, enable interactive consoles, and disable security defaults. Shipping with DEBUG=True, ALLOWED_HOSTS=*, or NODE_ENV=development exposes the app.

## Fix
See the rule description and the detector at `src/rules/debug_enabled_prod.cr`.
