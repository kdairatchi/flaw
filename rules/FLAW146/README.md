# FLAW146 — Kubernetes security boundary disabled

**Severity:** high · **Tag:** security · CWE-250

## What
Container escapes and host takeover frequently start from a manifest that waives a default security boundary — `privileged: true`, `hostNetwork`, `hostPID`, running as UID 0, disabling `readOnlyRootFilesystem`, or adding dangerous capabilities like SYS_ADMIN/NET_ADMIN/ALL. Keep the defaults and drop capabilities explicitly.

## Fix
See the rule description and the detector at `src/rules/k8s_privileged.cr`.
