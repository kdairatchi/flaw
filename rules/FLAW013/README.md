# FLAW013 — Insecure tempfile

**Severity:** medium · **Tag:** filesystem · CWE-377

## What
A tempfile path is built manually (or from `File.tempname`) and then written to. An attacker with local access can pre-create or symlink that path to clobber files the process has write access to.

## Fix
Use `File.tempfile(prefix, suffix) { |f| ... }` — it opens with `O_EXCL` and a random cryptographic suffix.
