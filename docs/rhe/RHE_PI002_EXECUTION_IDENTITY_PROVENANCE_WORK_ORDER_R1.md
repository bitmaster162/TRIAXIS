# TRIAXIS RHE / PI-002 — execution identity provenance hardening work order R1

Status: `REVIEW_REQUIRED_BEFORE_RHE_CANARY_MERGE`

## Finding

For `spiffe_workload` authorization tokens, `SQLiteExecutionLedger.prepare()` currently requires a caller-supplied `current_workload_identity` to be marked `VERIFIED` and field-correlated with the token. Provider provenance is checked only when both a trusted registry and a provider instance are supplied.

`VerifiedWorkloadIdentity` is an ordinary in-memory dataclass, not a cryptographically self-authenticating object. Therefore the current PREPARED boundary contains an implicit trusted-caller assumption.

## Decision

For the RHE execution boundary, choose the stricter contract: a SPIFFE-bound PREPARED transition must require trusted provider provenance as well as field correlation.

## Minimal candidate change

For tokens whose identity mode is `spiffe_workload`:

1. current workload identity must be `VERIFIED`;
2. `trusted_provider_registry` must be present;
3. `provider_instance` must be present;
4. the registry must trust the exact provider instance under `provider_id`;
5. current `spiffe_id`, `agent_instance_id`, and `trust_domain` must match the token;
6. certificate fingerprint equality is deliberately NOT required, preserving rotation-safe stable identity.

Legacy/non-SPIFFE token behavior is unchanged.

## Required tests

- trusted provider + freshly fetched matching identity => PREPARED;
- same token + same trusted workload => same PREPARED row;
- rotated certificate fingerprint with the same trusted SPIFFE/agent/trust-domain => PREPARED;
- current identity not VERIFIED => reject, no row;
- registry missing => `UNTRUSTED_IDENTITY_PROVIDER`, no row;
- registry present but provider instance missing => `UNTRUSTED_IDENTITY_PROVIDER`, no row;
- wrong/unregistered provider instance => `UNTRUSTED_IDENTITY_PROVIDER`, no row;
- SPIFFE mismatch => reject, no row;
- agent mismatch => reject, no row;
- trust-domain mismatch => reject, no row;
- cross-workload replay remains rejected;
- nonce/idempotency semantics remain unchanged.

## Compatibility check

Before merge, identify all repository call sites of `prepare_for_workload` / SPIFFE-bound `prepare` and update legitimate callers to pass trusted registry + exact provider instance. The existing PI-002 tests include registry-less calls and therefore must be migrated deliberately rather than silently preserved as security authority.

## Boundaries

- no merge
- no deploy
- no external execution
- no AWS
- no trading
- no capital
- `can_trade=false`
- `capital_permission=DENY`

Independent review terminal:

`PASS_PI002_EXECUTION_IDENTITY_PROVENANCE_HARDENING`

or

`REVISE_PI002_EXECUTION_IDENTITY_PROVENANCE_HARDENING`
