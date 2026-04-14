# FLAW148 — Source map shipped in production artifact

**Severity:** medium · **Tag:** security · CWE-540

## What
A `sourceMappingURL` pragma was found in a bundle under a published artifact path (dist/, build/, out/, lib/), or a `.map` filename is listed in package.json's `files:` allowlist. Shipping source maps reconstructs the original TypeScript/JavaScript for anyone who pulls the package — strip them from the published tarball.

## Fix
See the rule description and the detector at `src/rules/source_map_shipped.cr`.
