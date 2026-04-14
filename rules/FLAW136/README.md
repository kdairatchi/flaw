# FLAW136 — Cloud metadata endpoint

**Severity:** medium · **Tag:** security · CWE-918

## What
Hardcoded references to cloud instance metadata endpoints (169.254.169.254, metadata.google.internal, metadata.azure.com) often mark either an SSRF exploit payload or tooling that reads instance credentials — both need a review.

## Fix
See the rule description and the detector at `src/rules/cloud_metadata_ref.cr`.
