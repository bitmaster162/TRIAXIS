# TRIAXIS RHE Complete Mediation Hardening R1

Authority base: `90737239f2c77ad51410a32b40f90d2e6b3b5e13`

Approved scope: `RAW_PREPARED_BYPASS_AND_SIGNER_ISSUER_BINDING_ONLY`.

## Security invariant

An `AuthenticatedSQLiteExecutionLedger` must not create `PREPARED` state through the inherited unauthenticated `SQLiteExecutionLedger.prepare()` surface. Authenticated preparation is permitted only after the existing `prepare_authenticated()` path has validated the signed authorization token, the signed risk-mediation receipt bound to that exact token/effect/risk, and the signed state witness.

A cryptographically valid authorization-token envelope is not sufficient when the verified envelope signer is different from the token's declared `issuer_id`. Authenticated authorization fails closed on that mismatch.

## R1 changes

1. Override `AuthenticatedSQLiteExecutionLedger.prepare()` to fail closed with `RISK_MEDIATION_AUTHENTICATION_REQUIRED`. The inherited `prepare_for_workload()` path also reaches this override and therefore cannot bypass authenticated mediation.
2. Keep `prepare_authenticated()` as the only authenticated route to the parent ledger's PREPARED implementation; after all authenticated checks pass it deliberately calls `super().prepare(...)`.
3. Extend `validate_authenticated_authorization()` with exact `verified_signer.signer_id == token.issuer_id` enforcement.
4. Add zero-effect regression tests proving both bypass closure and signer/issuer mismatch rejection while preserving the valid mediated PREPARED path.

## Explicit non-goals

This R1 does not change the legacy `SQLiteExecutionLedger` contract, Cedar policy semantics, R4 HUMAN floors, `DEPLOYMENT` risk classification, cross-process RiskFacts provenance, production mediation-ledger persistence, external provider/effect lifecycle, deployment, trading, capital permission, or model execution.

## Effect boundary

Tests are limited to deterministic in-process fixtures, ephemeral Ed25519 test keys, trusted in-memory registries and disposable SQLite state. No real provider invocation, AWS call, production ledger mutation, deployment, trading, capital action or model execution is authorized by this change.
