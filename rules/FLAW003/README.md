# FLAW003 — SQL Injection via String Building

**Severity:** high · **Tag:** injection · **CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

## What

A SQL statement is constructed with string interpolation (`"... \#{var}"`) or `+` concatenation and then handed to a DB driver. Any attacker-controlled value becomes part of the query.

## Fix

Use placeholders the driver handles — `?` for crystal-db, driver-specific positional tokens for others.

```crystal
# bad
db.query("SELECT * FROM users WHERE id = #{id}")

# good
db.query("SELECT * FROM users WHERE id = ?", id)
```

For `LIKE` queries, interpolate the wildcards onto the parameter value, not into the SQL.
