# TRIAXIS v2.9-RC1 — Operator Card

## Ingress order

```text
SOURCE / SPANS / MODALITY / AUTHORITY PROVENANCE
-> SEMANTIC INGRESS RECEIPT
-> STRUCTURED INPUT CONTRACT v2
-> ROUTER E#/X#
-> MATERIAL GOVERNANCE GATES
-> DECISION / PERMISSION / DELTA
```

## Action floor

| Action | Minimum X |
|---|---:|
| ANALYZE, READ | 0 |
| WRITE, EXECUTE, DELETE | 1 |
| SEND, PUBLISH, DEPLOY | 2 |
| SPEND, TRADE, MODIFY_ACCESS, HANDLE_SECRETS | 3 |

Underclassification: `BLOCKED_BY_INPUT_CONTRACT`.

## Semantic ingress blockers

- source/span digest mismatch;
- quoted, external, question or hypothetical text used as authority;
- missing or false field provenance;
- explicit action omitted or mapped to another node;
- ambiguous material target in `VALID` extraction;
- dependency cycle or unknown dependency;
- sensitive SEND/PUBLISH without Data Gate.

Invalid: `BLOCKED_BY_SEMANTIC_INGRESS`. Ambiguous: `HUMAN_DECISION_REQUIRED`.

## X0 is not gate-free

When explicitly active, check binding, preconditions, budget and verification before ALLOW. Reliance and policy limits accumulate; they never mask a hard blocker.

## Required receipts

```text
SEMANTIC_INGRESS_CONTRACT_ID
INPUT_CONTRACT_ID
FRAME_VERSION / EVIDENCE_SET_ID
ACTIVE_CONTROLS / SKIPPED_CONTROLS
DECISION + PRIMARY_REASON
PERMISSION_STATUS when X>0
STATE_DELTA / STOP_STATE
```

## Status boundary

Passing deterministic tests means only `VERIFIED_WITHIN_SCOPE`. It does not establish general natural-language understanding, independent validation, live execution safety or Production-qualified status.
