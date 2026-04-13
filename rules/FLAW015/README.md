# FLAW015 — Mass assignment of privilege fields

**Severity:** medium · **Tag:** access-control · CWE-915

## What
A struct including `JSON::Serializable` exposes `admin`, `role`, `is_admin`, `permissions`, etc. as writable properties. `from_json(request.body)` will happily set them from client-controlled JSON.

## Fix
Split read and write DTOs, or annotate sensitive fields with `@[JSON::Field(ignore: true)]` on the write side.
