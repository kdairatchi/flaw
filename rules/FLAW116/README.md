# FLAW116 — Unsafe deserialization sink

**Severity:** high · **Tag:** security · CWE-502

## What
pickle, cPickle, dill, shelve, Ruby Marshal, YAML.unsafe_load and Oj without a safe mode will execute arbitrary code embedded in the byte stream. Use JSON, MessagePack, or explicitly safe loaders.

## Fix
See the rule description and the detector at `src/rules/unsafe_deserialize_pickle.cr`.
