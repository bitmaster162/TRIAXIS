# TRIAXIS RHE / PI-002 — bounded hardening work order R1

Status: `DESIGN/REVIEW ONLY`

## Problem

`SQLiteExecutionLedger.prepare_for_workload()` can accept a caller-supplied `VerifiedWorkloadIdentity` without proving that the object came from a trusted provider at execution-preparation time.

Authorization issuance already has a trusted-provider boundary. This work order concerns only execution-time provenance before the PREPARED transition.

## Goal

Choose and implement the smallest fail-closed contract that preserves rotation-safe SPIFFE ownership while removing silent provenance downgrade.

## Candidate contract

For tokens whose identity mode is `spiffe_workload`:

1. `current_workload_identity` must be VERIFIED.
2. `trusted_provider_registry` must be present unless an explicit compatibility downgrade is enabled.
3. `provider_instance` must be present and trusted by the registry.
4. current identity fields must match the token's authorized SPIFFE ID, agent instance and trust domain.
5. same SPIFFE ID/agent/trust-domain with a rotated certificate fingerprint remains acceptable.
6. synthetic matching identity with no trusted provider provenance must not reach PREPARED in strict mode.

## Compatibility question

Before product-source changes, decide whether any existing production caller intentionally relies on registry-less `prepare_for_workload`.

If yes, introduce an explicit compatibility flag defaulting fail-closed for new RHE/production use and migrate callers deliberately.

If no, require registry + provider instance unconditionally for `spiffe_workload` tokens.

## Required tests

- trusted provider + freshly fetched matching identity -> PREPARED
- same token + same trusted workload -> same PREPARED row
- rotated cert fingerprint, same trusted stable identity -> PREPARED
- current identity not VERIFIED -> DENY
- synthetic matching VERIFIED object, registry absent -> DENY in strict mode
- registry present, provider instance missing -> DENY
- registry present, wrong provider instance -> DENY
- current SPIFFE mismatch -> DENY
- current agent mismatch -> DENY
- trust-domain mismatch -> DENY
- rejected attempt leaves no new row

## Boundaries

- no merge
- no deploy
- no external execution
- no AWS
- no trading
- no capital
- can_trade=false
- capital_permission=DENY

Allowed next terminal after independent code/test review:

`PASS_PI002_EXECUTION_IDENTITY_PROVENANCE_HARDENING`

or

`REVISE_PI002_EXECUTION_IDENTITY_PROVENANCE_HARDENING`
