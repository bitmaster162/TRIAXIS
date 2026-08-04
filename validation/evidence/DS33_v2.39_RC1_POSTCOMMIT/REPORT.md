# TRIAXIS v2.39-RC1 Recovery — Post-Commit Durability Trigger

```text
EXACT PRODUCT COMMIT:       3ae20af5e735128d3ea8e219e11d4d2c6e1893da
EXACT PRODUCT TREE:         04a5e2458e010a92301e318d35f854ab38983219
PROTOCOL:                   TRIAXIS_AUTHORITY_CHECKPOINT_DURABILITY_TRIGGER_v3.3_RECOVERY
RESULT:                     FAIL AS TRIGGERED
CASES:                       4 / 10 PASS
FAILURES:                    6 / 10
POSITIVE CONTROLS:           4 / 4 PASS
HISTORICAL TESTS:           80 / 80 PASS
REPRODUCIBILITY:            byte-identical across two detached process invocations
RESULTS SHA-256:            ff346bc3b223500f1456d104a203268ef8f3e60627e6b34ff07cf5fb6d38bdc8
SUMMARY SHA-256:            a6acf1b6a9a37ebe125f2c6bb55ca0f4c6eac03359e0d42fbe3295365b1853f5
PROTOCOL ROWS SHA-256:      a347f48e09796e66822927ca73a782ebad967e1406dada23bdbf91ea4742ccf5
```

## Triggered defect

v2.39 can authenticate one exact restart pair, but it delegates durable storage
and generation coordination to the caller. The exact product exposes no local
transactional store, so all six durability cases report
`checkpoint_store_api_missing` while all four restore controls remain valid.

## Required correction

Add a namespace-scoped SQLite store that validates an exact receipt/envelope pair,
uses one transaction for current-head and immutable-history writes, enforces
sequence/parent/root continuity and compare-and-swap, reopens cleanly, and leaves
state unchanged on invalid input or stale CAS. Loading must still require the
host-controlled expected-head digest.

Same-lineage evidence only; not power-loss certification, whole-database
anti-rollback, multi-host consensus, production qualification or external action
authority.
