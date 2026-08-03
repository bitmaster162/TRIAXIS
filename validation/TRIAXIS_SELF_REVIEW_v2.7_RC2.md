# TRIAXIS v2.7-RC2 — Validation-State Self-Review

```text
RUN_ID: TRIAXIS-v2.7-RC2-SELF-2026-08-03
META_DEPTH: 2
PARENT_VERSION: v2.7-RC1
LOGIC_DELTA: NONE
P2_CASE_SHA256: 81d31c8041fd3a52291f8716253510824ee4b5efd5e6e46c4bafb84bcd1a0f3f
P2_RESULT_SHA256: b9e9c6e1402ac94f36439e4c17611510ffdb3d507db0ffc5d6afb3a4dc232162
P2_RESULT: PASS 32 / FAIL 0
```

Audit: RC2 must remain behaviorally identical to RC1.  
Devil: deterministic case relations still assume structurally valid input. Missing fields, wrong types and typos may bypass gates or crash the projection.  
Angel: P2 confirms the v2.7 composition patch on a fresh exact batch.  
Synthesis: record the validation state and move to strict input-contract fault injection.

```text
ANALYSIS_STATUS: PASS_WITH_CONDITIONS
SPECIFICATION: TRIAXIS v2.7-RC2
HOLDOUT: 96/96
METAMORPHIC: P1 32/32 regression + P2 32/32 fresh
NEXT_EVIDENCE: INPUT CONTRACT / OMIT / TYPE / UNKNOWN-FIELD FAULTS
```
