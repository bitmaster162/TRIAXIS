# TRIAXIS Conformance Suite v1.0

```text
CURRENT CANDIDATE: v2.8-RC2
ISOLATED HOLDOUTS H1–H4: PASS 96 / FAIL 0
METAMORPHIC P1/P2: PASS 64 / FAIL 0
INPUT Q1/Q2: PASS 56 / FAIL 0
TOTAL FROZEN BATCH RELATIONS: PASS 216 / FAIL 0
FULL INPUT FAULT TEMPLATE BANK: PASS 39 / FAIL 0
```

Evidence classes:

- H1–H4: historical commit-sealed holdout/regression evidence;
- P1: patch-triggering metamorphic evidence;
- P2: fresh metamorphic evidence for v2.7 logic;
- Q1: patch-triggering input-contract evidence;
- Q2: fresh commit-bound input-contract evidence for v2.8 logic.

The suite validates deterministic structured gates only. It does not establish independent assurance, natural-language extraction completeness, generative control-pass quality, live tool safety or production qualification.
