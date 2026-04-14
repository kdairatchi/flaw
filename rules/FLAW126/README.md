# FLAW126 — Shell execution with interpolation

**Severity:** high · **Tag:** security · CWE-78

## What
Passing an interpolated string to system/exec/backticks/Process.run with shell:true hands the shell the entire command, letting any metacharacter in the interpolated value inject arbitrary commands. Use the array form and keep shell:false.

## Fix
See the rule description and the detector at `src/rules/shell_exec.cr`.
