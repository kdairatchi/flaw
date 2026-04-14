# FLAW133 — NoSQL injection sink

**Severity:** high · **Tag:** security · CWE-943

## What
$where / $function operators evaluate arbitrary JavaScript inside MongoDB. Passing user input into them is remote code execution. Passing non-literal query objects built from request data risks operator injection (e.g. {"$gt": ""} to bypass auth).

## Fix
See the rule description and the detector at `src/rules/nosql_injection.cr`.
