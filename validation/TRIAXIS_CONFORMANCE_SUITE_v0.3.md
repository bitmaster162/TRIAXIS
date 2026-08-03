# TRIAXIS Conformance Suite v0.3

## Added evidence

H1-v2.3 was generated only after candidate and validation framework commit `9504077b95b82f733ff5ee56d5b2c7f4d632b4ee` existed.

```text
BATCH: H1-v2.3
CASES: 24
CASE_SHA256: a97044760755316801d0c6dcd9de839c9f00e1947386108953ea3aeb6d6cba8b
RESULT_SHA256: 69b6de4616ac4d8d69788cfea98d72822ad48f17c83ea2fd5fa0545e56585627
V2.3: PASS 11 / FAIL 13
```

Observed failure classes:

```text
AUTHORITY_QUORUM
DELEGATION
POLICY_BINDING
TOOLCHAIN_BINDING
CAPABILITY_EVIDENCE_TRUST
DOWNSTREAM_RELIANCE
DATA_LINEAGE
TRACE_DISCLOSURE
ATOMIC_BUDGET_RESERVATION
ATOMIC_COMPARE_AND_COMMIT
IDEMPOTENCY_PAYLOAD_BINDING
RESUME_INTEGRITY
LEDGER_INTEGRITY
```

H1 becomes regression evidence after v2.4 is patched. A fresh H2 derived from the frozen v2.4 commit is required for any new validation claim.

## v2.4 H1 regression

```text
V2.4-RC1: PASS 24 / FAIL 0
CASE_SHA256: a97044760755316801d0c6dcd9de839c9f00e1947386108953ea3aeb6d6cba8b
RESULT_SHA256: 0d878762e1d50f4ce05e3ee74acadced659ef20aaa6da8dafdda75b4a6210340
CLASSIFICATION: regression evidence, not fresh holdout evidence
```
