# PI-002 execution identity provenance — minimal patch spec R1

This spec authorizes only a bounded candidate on a separate branch. It does not authorize merge/deploy.

## Exact product change

In `SQLiteExecutionLedger.prepare()`:

When the token is bound to `spiffe_workload` identity:

1. Require `current_workload_identity.verification_status == VERIFIED` (existing behavior).
2. Require `trusted_provider_registry` to be non-null.
3. Require `provider_instance` to be non-null.
4. Require `trusted_provider_registry.is_provider_trusted(provider_id, provider_instance) == true`.
5. Only then compare current SPIFFE ID, agent instance and trust domain against the authorization token.

For non-SPIFFE/legacy tokens, no new provider requirement is introduced.

## Explicitly unchanged

- no certificate-fingerprint equality requirement (rotation-safe stable identity remains supported);
- no external provider/network call added inside the ledger;
- no AWS;
- no signing;
- no trading/capital/deploy;
- no change to token issuance or Cedar policy semantics;
- no change to nonce/idempotency transaction semantics.

## Required test migrations

Existing PI-002 tests that intentionally exercise SPIFFE-bound PREPARED must pass a trusted registry + exact provider instance.

New fail-closed tests must prove:

- registry missing => `UNTRUSTED_IDENTITY_PROVIDER`, no row;
- registry present/provider missing => `UNTRUSTED_IDENTITY_PROVIDER`, no row;
- wrong provider instance => `UNTRUSTED_IDENTITY_PROVIDER`, no row;
- trusted provider + matching verified identity => PREPARED;
- trusted provider + rotated fingerprint but same stable identity => PREPARED;
- cross-workload mismatch remains rejected;
- same-token/same-workload retry remains idempotent.

## Gate

Candidate branch must be created from exact `main @ ae280d905c63e4ba0bcadb4633f01a1fb9657920` unless main has advanced, in which case stop and re-baseline.

`MERGE=DENY`
`DEPLOY=DENY`
`can_trade=false`
`capital_permission=DENY`
