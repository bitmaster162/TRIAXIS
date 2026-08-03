# TRIAXIS Input Contract Fault Protocol v1.0

## Purpose

Detect fail-open defaults, parser crashes, typo bypasses and unsafe coercions before governance gates run.

## Required behavior

Malformed, incomplete or type-invalid structured input must produce a deterministic fail-closed result:

```text
status: BLOCK
primary_reason: BLOCKED_BY_INPUT_CONTRACT
```

It must not:

- default a missing safety field to `ALLOW`;
- coerce strings such as `"false"` to truthy booleans;
- accept unknown enum values;
- ignore misspelled safety-critical fields;
- crash before producing a receipt;
- report a downstream gate as if malformed input were valid evidence.

## Scope limitation

This protocol tests the structured deterministic projection. It does not validate natural-language extraction into that structure.
