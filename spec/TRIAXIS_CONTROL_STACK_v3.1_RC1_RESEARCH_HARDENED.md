# TRIAXIS Control Stack v3.1-RC1 — Research-Hardened Assurance

## Trigger

The exact v3.0-RC1 product commit passed historical tests but failed 7 of 8 fresh post-commit cases. The failures proved that structural role diversity was still being accepted without evidence independence, temporal validity, blind-review metadata or test-evidence binding.

## Changes from v3.0

1. Decision Assurance Case contract bumped to v2.
2. Intake now binds `evaluation_tick`, allowed tools, forbidden outcomes and approvals.
3. Every epistemic branch declares `input_mode`:
   - `FULL_CONTEXT`;
   - `BLIND_ARTIFACT`;
   - `INDEPENDENT_RETRIEVAL`.
4. A2/A3 Devil, Falsifier and Independent Reviewer may not use `FULL_CONTEXT`.
5. Evidence binds `observed_at`, optional `valid_until`, verification mode, source group and content SHA-256.
6. Expired and future evidence block the case.
7. Falsification binds an exact Falsifier branch and verifier-grade test evidence.
8. R3/R4 independent review requires both heterogeneous branch identity and an evidence source group not used by Primary.
9. Load-bearing `UNVERIFIED_ASSUMPTION` produces `ESCALATE`, never `PASS`.
10. Gate payload SHA-256 and expiry are validated.
11. Exactly one Primary is required.

## New invariant

```text
independent review
= structurally distinct branch
+ isolated input path
+ evidence outside the Primary correlation group
```

Different provider or model labels alone are insufficient.

## Scope

The implementation validates declared metadata and canonical digests. Provider identity, model identity, source grouping and evidence origin are not yet cryptographically attested by an external registry. This is a known remaining boundary, not a production guarantee.
