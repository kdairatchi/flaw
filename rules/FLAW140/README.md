# FLAW140 — LOLBIN abuse signature

**Severity:** high · **Tag:** security · CWE-506

## What
Windows ships signed binaries (regsvr32, mshta, certutil, bitsadmin, rundll32, wmic, installutil, cscript) that attackers chain to bypass AV/EDR. Source code should never invoke them with the exploit flags.

## Fix
See the rule description and the detector at `src/rules/lolbin_abuse.cr`.
