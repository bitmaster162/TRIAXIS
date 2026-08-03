# TRIAXIS v2.5-RC1 — Release Notes

## Evidence trigger

Fresh H2 against frozen v2.4-RC1 produced 23 PASS / 1 FAIL. The sole mismatch treated correlated evidence as independent.

## Change

Added Evidence Origin Graph and common-cause analysis across upstream sources, datasets/events, collection paths, transformations, model/tool chains, organizational control and relevant failure domains.

```text
NEW STATUS: ESTABLISHED | PARTIAL | CORRELATED | UNKNOWN | NOT_REQUIRED
NEW BLOCKER: BLOCKED_BY_CORRELATED_EVIDENCE
```

## Scope

This patch does not prove source independence automatically. It requires an explicit basis and limits claims when independence is partial or unknown.

## Regression receipt

```text
H1: PASS 24 / FAIL 0
H2: PASS 24 / FAIL 0
UNIT TESTS: PASS 6 / FAIL 0
```
