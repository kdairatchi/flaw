# FLAW138 — PowerShell encoded/hidden command

**Severity:** high · **Tag:** security · CWE-506

## What
PowerShell invoked with `-EncodedCommand` or `-WindowStyle Hidden -NoProfile` is the hallmark of living-off-the-land malware droppers. Source trees should never ship such lines; investigate anything that matches.

## Fix
See the rule description and the detector at `src/rules/powershell_encoded.cr`.
