# Authenticated Terminal Effect Bridge R1

Status: reference hardening only. No deploy, provider invocation, trading, capital action, or model execution. This change does not establish repository-wide complete mediation or production qualification.

## Problem

The v3.32 `verify_terminal_external_effect_guard` is intentionally a local-reference composition helper. It accepts two caller-supplied authority surrogates:

- `separate_authorization_valid: bool`
- `v331_guard_result: Mapping`

Those values are adequate for the historical reference composition but are not cryptographic action authority. A caller can construct `True` or a PASS-shaped mapping without proving that a current signed ALLOW token, authenticated risk mediation, and the exact v3.31 evidence path authorize the same effect.

## R1 boundary

`verify_authenticated_terminal_external_effect_guard` adds a separate authenticated RHE composition path. The legacy helper is retained unchanged in behavior and explicitly documented as non-authoritative.

The authenticated boundary requires:

1. a signed authorization token that passes `validate_authenticated_authorization` at the exact evaluation tick;
2. a signed risk-mediation receipt that passes `validate_authenticated_risk_mediation` under the token signer's identity and trust domain;
3. a valid sealed `ExecutionIntent`;
4. exact token binding: `intent.authorization_token_sha256 == token.token_sha256`;
5. exact action binding: `intent.action_envelope_sha256 == token.action_sha256`;
6. exact target binding: `intent.canonical_target_sha256 == canonicalize_tool_target(token.execution_target).target_sha256`;
7. exact payload binding across token, v3.31 preflight, and provider-native verification;
8. exact provider/service identity binding across v3.31, provider-native, and completion-transparency verification;
9. one common evaluation tick across authorization and all terminal evidence verifiers.

The new boundary invokes `verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor` itself. It does not accept a precomputed `v331_guard_result`, and it does not accept a boolean authorization surrogate.

Only after authenticated authority and all exact bindings pass does it evaluate provider-native and completion-transparency evidence and return `external_effect_permitted=True`.

## Fail-closed cases

R1 blocks before terminal evidence evaluation on:

- invalid, forged, DENY, or expired signed authorization;
- missing or invalid signed risk-mediation receipt;
- token/intent SHA mismatch;
- action-envelope mismatch;
- canonical-target mismatch;
- provider payload substitution;
- provider/service identity substitution;
- evaluation-tick substitution.

A failed or authority-expanding v3.31 result also blocks.

## Test boundary

`tests/test_rhe_effect_bridge_r1.py` uses real Ed25519 authorization and risk-mediation fixtures and mocked durability/transparency verifiers. The mocks prevent external effects while proving that the authenticated bridge, rather than a caller-provided PASS mapping, performs the v3.31 invocation and pins exact effect inputs.

The test is intentionally not a replacement for the existing v3.31/v3.32 closure suites. Those suites continue to prove their respective evidence-plane behavior.

## Residuals

- The legacy v3.32 helper remains public for compatibility and is not complete-mediation authority.
- The new boundary is still a local reference verifier and does not itself invoke a provider.
- Provider transport authentication, production deployment topology, repository-wide call-site containment, and proof that every effect-capable entrypoint is forced through this boundary remain separate integration work.
- No production or exactly-once claim is added by R1.
