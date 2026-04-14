# FLAW123 — Prototype pollution sink

**Severity:** high · **Tag:** security · CWE-1321

## What
Deep-merging user-controlled objects into targets — or writing to __proto__/constructor.prototype — lets an attacker inject properties onto Object.prototype. Use Object.create(null), a Map, or a schema-validating merge.

## Fix
See the rule description and the detector at `src/rules/prototype_pollution.cr`.
