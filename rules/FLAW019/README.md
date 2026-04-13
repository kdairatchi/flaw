# FLAW019 — Cookie missing Secure / HttpOnly / SameSite

**Severity:** medium · **Tag:** cookie · CWE-1004

## What
Session cookies without `HttpOnly` are stealable via XSS; without `Secure` they leak over HTTP; without `SameSite` they enable CSRF.

## Fix
Always pass `secure: true, http_only: true, samesite: :strict` (or `:lax`) when creating cookies that carry authentication or identity.
