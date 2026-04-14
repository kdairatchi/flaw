# FLAW154 — Prefix check without canonicalization

**Severity:** high · **Tag:** security · CWE-23

## What
A path is validated with `startswith`/`HasPrefix`/`starts_with` before the path is canonicalized. Symlinks or `..` segments bypass the check. Canonicalize (`os.path.realpath`, `Path.resolve`, `filepath.EvalSymlinks`, `Path::canonicalize`) before the prefix comparison, or compare against an absolute allowlist with the canonical form.

## Fix
See the rule description and the detector at `src/rules/path_prefix_check.cr`.
