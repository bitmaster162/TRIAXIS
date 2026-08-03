# TRIAXIS v2.6-RC1 — Release Notes

## Evidence trigger

Fresh H3 against frozen v2.5-RC1 produced 23 PASS / 1 FAIL: a normative payload with manifest mismatch was allowed.

## Change

Added Release Integrity Gate with exact normative file set, per-file SHA-256 manifest, component version compatibility, source commit binding, immutable payload after manifest, and separate archive-hash sidecar.

```text
NEW STATUS: NOT_PREPARED | PREPARED | VERIFIED | FAILED | SUPERSEDED | NOT_REQUIRED
NEW BLOCKER: BLOCKED_BY_RELEASE_INTEGRITY
```

## Regression receipt

```text
H1: PASS 24 / FAIL 0
H2: PASS 24 / FAIL 0
H3: PASS 24 / FAIL 0
UNIT TESTS: PASS 9 / FAIL 0
```
