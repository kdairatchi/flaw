# FLAW017 — Regex ReDoS candidate

**Severity:** low · **Tag:** dos · CWE-1333

## What
A regex literal contains a nested quantifier like `(a+)+`, `(a*)*`, or `(a|a)+`. Against a crafted input this takes exponential backtracking time and stalls the process.

## Fix
Rewrite the pattern to avoid nesting. Use disjoint character classes with greedy tokens so the engine can't backtrack ambiguously.
