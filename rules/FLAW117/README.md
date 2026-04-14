# FLAW117 — target=\

**Severity:** low · **Tag:** security · CWE-1022

## What
An anchor/area/form opens in a new tab via target="_blank" but does not set rel="noopener" (or noreferrer). The opened document can navigate window.opener — reverse tabnabbing. Add rel="noopener noreferrer".

## Fix
See the rule description and the detector at `src/rules/unsafe_target_blank.cr`.
