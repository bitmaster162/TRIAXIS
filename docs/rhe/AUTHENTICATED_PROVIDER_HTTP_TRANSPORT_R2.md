# Authenticated Provider HTTP Transport R2

Status: reference hardening only. No deploy, provider invocation, trading, capital action, or model execution. This change does not establish repository-wide complete mediation or production qualification.

## Problem

The legacy v3.28 `IdempotentEffectProviderHTTPApplication` protects mutation routes with a static Bearer-token hash. For `/v1/effects/begin`, successful transport authentication is sufficient to call `provider.begin(...)`, which can return `external_effect_permitted=True` for a new effect.

That is transport authentication, not authenticated RHE action authority.

PR27 added `verify_authenticated_terminal_external_effect_guard`, which cryptographically binds signed ALLOW authorization, signed risk mediation, the exact sealed `ExecutionIntent`, v3.31 terminal evidence, provider-native evidence, provider/service identity, payload and evaluation tick. The legacy provider HTTP entrypoint did not require that bridge.

## R2 boundary

`AuthenticatedIdempotentEffectProviderHTTPApplication` is a separate opt-in HTTP mode. The legacy class is retained for compatibility and explicitly remains non-authoritative.

For `POST /v1/effects/begin`, the authenticated mode requires:

1. the historical Bearer transport credential;
2. a signed authorization token;
3. a signed risk-mediation receipt;
4. the sealed execution intent;
5. signed in-flight / terminal evidence required by the PR27 bridge;
6. server-side pinned provider and service identity;
7. one server clock tick supplied to the authenticated terminal bridge;
8. a bridge result with `status=PASS`, `external_effect_permitted=True`, no authority expansion, and `authenticated_terminal_effect_bridge=True`.

Only then can the reference provider's `begin(...)` method be called.

## Exact identity derivation

The effect initiation identity is not trusted from caller top-level fields:

- `effect_id` comes from the successful authenticated terminal bridge result;
- `payload_sha256` comes from the same signed authorization token that the bridge verified;
- `provider_id` and `service_id` are pinned from the server-side provider object into all terminal verification kwargs;
- `provider_request_id` remains a transport/request identity and does not grant action authority.

If caller-supplied top-level `effect_id` or `payload_sha256` fields are present, they must match the authenticated values exactly or the request blocks before `provider.begin(...)`.

## Fail-closed cases

Effect initiation blocks before provider mutation on:

- Bearer-only requests missing authenticated evidence;
- rejected or malformed authenticated terminal bridge evidence;
- authority expansion or non-PASS bridge result;
- provider/service configuration substitution;
- effect-id substitution;
- payload substitution;
- missing provider request identity;
- invalid server evaluation tick.

## Compatibility boundary

The historical `IdempotentEffectProviderHTTPApplication` retains its existing v3.28 behavior. This is deliberate because v3.28 is a reference idempotency/reconciliation primitive and existing closure tests depend on that contract.

`AuthenticatedIdempotentEffectProviderHTTPApplication` hardens only `/v1/effects/begin`. Outcome recording, reconciliation and outcome-receipt routes keep their historical transport-authenticated behavior because they do not initiate a new external effect.

## Test boundary

`tests/test_rhe_provider_http_r2.py` uses a mocked provider and mocked PR27 terminal bridge. It proves transport wiring and fail-closed ordering without performing a provider effect or network call:

- legacy begin behavior remains compatible;
- Bearer-only authenticated-mode begin is blocked before bridge/provider invocation;
- bridge failure blocks provider begin;
- exact PASS calls provider begin exactly once with authenticated-derived effect/payload bindings;
- caller effect/payload substitution blocks before provider mutation;
- server-side provider identity substitution fails closed.

PR27's existing bridge tests remain the authority for the real Ed25519 authorization/risk-mediation composition.

## Residuals

- This R2 closes the primary reference HTTP effect-initiation bypass only.
- Direct calls to legacy/reference provider primitives remain possible by design and are not repository-wide complete mediation.
- A final repository-wide effect-capable call-site census is still required before any stronger complete-mediation claim.
- No real vendor/provider effect, deployment topology, production gateway, exactly-once behavior, trading, capital action, or model execution is established by this change.
