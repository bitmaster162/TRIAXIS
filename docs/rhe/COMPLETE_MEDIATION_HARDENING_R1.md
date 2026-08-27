# TRIAXIS RHE Complete Mediation Hardening R1

Authority base: `90737239f2c77ad51410a32b40f90d2e6b3b5e13`

Approved scope: `RAW_PREPARED_BYPASS_AND_SIGNER_ISSUER_BINDING_ONLY`, with bounded FIX_R3 closure of explicit public base-class `prepare()` dispatch on an authenticated ledger instance.

## Security invariant

An `AuthenticatedSQLiteExecutionLedger` must not create `PREPARED` state through the public unauthenticated `SQLiteExecutionLedger.prepare()` surface, including normal inherited dispatch and an explicit call such as `SQLiteExecutionLedger.prepare(authenticated_ledger, ...)`. Authenticated preparation through the supported authenticated API is permitted only after `prepare_authenticated()` has validated the signed authorization token, the signed risk-mediation receipt bound to that exact token/effect/risk, and the signed state witness.

A cryptographically valid authorization-token envelope is not sufficient when the verified envelope signer is different from the token's declared `issuer_id`. Authenticated authorization fails closed on that mismatch.

## R1 changes

1. Keep `SQLiteExecutionLedger.prepare()` as the public legacy entrypoint for ordinary legacy ledger instances, but make it fail closed with `RISK_MEDIATION_AUTHENTICATION_REQUIRED` when the ledger class requires authenticated preparation. Its unchanged PREPARED implementation is factored into the internal `_prepare_legacy()` helper.
2. Mark `AuthenticatedSQLiteExecutionLedger` as requiring authenticated preparation and retain its direct `prepare()` fail-closed override. The inherited `prepare_for_workload()` path and explicit public base-class `SQLiteExecutionLedger.prepare(authenticated_ledger, ...)` path therefore cannot enter the raw PREPARED implementation.
3. Keep `prepare_authenticated()` as the supported authenticated route to PREPARED; only after authenticated token, mediation and state checks pass does it call the internal parent `_prepare_legacy()` implementation.
4. Extend `validate_authenticated_authorization()` with exact `verified_signer.signer_id == token.issuer_id` enforcement.
5. Add zero-effect regression tests proving the ordinary raw call, inherited workload call, and explicit public base-class call all fail closed without a ledger row, while the valid mediated authenticated path still reaches PREPARED and signer/issuer mismatch still blocks.

## Explicit non-goals

This R1 does not remove the legacy `SQLiteExecutionLedger` API for ordinary legacy ledger instances. It does not prove repository-wide complete mediation, make lower-level `TrustedWorkloadExecutionBoundary.prepare()` mediated by itself, or claim that Python-private/internal helpers are a security boundary against hostile same-process code that can deliberately subvert object internals. The FIX_R3 guarantee is specifically about the supported/public raw `prepare()` surface, including explicit base-class dispatch on an authenticated ledger instance.

Also unchanged: Cedar policy semantics, R4 HUMAN floors, `DEPLOYMENT` risk classification, cross-process RiskFacts provenance, production mediation-ledger persistence, external provider/effect lifecycle, deployment, trading, capital permission, or model execution.

## Effect boundary

Tests are limited to deterministic in-process fixtures, ephemeral Ed25519 test keys, trusted in-memory registries and disposable SQLite state. No real provider invocation, AWS call, production ledger mutation, deployment, trading, capital action or model execution is authorized by this change.
