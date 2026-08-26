# RHE / PI-002 — Execution-time identity provenance finding R1

Classification: `REVIEW_REQUIRED_BEFORE_RHE_CANARY_MERGE`

This is a trust-boundary finding, not a claim that SPIFFE/X509 verification itself is broken.

## Observed behavior

`SQLiteExecutionLedger.prepare_for_workload(...)` validates:

1. authorization token is valid and ALLOW;
2. `current_workload_identity.verification_status == VERIFIED`;
3. current `spiffe_id`, `agent_instance_id` and trust domain match token authorization metadata;
4. **only if both** `trusted_provider_registry` and `provider_instance` are supplied, the provider object is checked through `registry.is_provider_trusted(...)`.

Therefore a caller may omit the registry/provider provenance check and supply an in-memory `VerifiedWorkloadIdentity` object whose fields match the token.

The dataclass is immutable but not cryptographically self-authenticating; ordinary Python code can construct one.

## Existing accepted test behavior

The existing PI-002 adversarial suite intentionally calls `prepare_for_workload` with manually constructed `VerifiedWorkloadIdentity` objects and no trusted provider registry/provider instance. It proves field-level token/workload correlation, but does not prove execution-time provider provenance.

This means the previously reported properties:

- trusted provider boundary;
- workload token binding;

are both real, but they apply at different layers. The authorization issuance path enforces provider trust; the ledger execution-preparation path can trust a caller-supplied VERIFIED identity object.

## Threat interpretation

### If `prepare_for_workload` is an internal API behind a separately trusted mediation component

This may be an acceptable explicit trust assumption. The contract must state:

`CURRENT_WORKLOAD_IDENTITY_OBJECT_IS_TRUSTED_INPUT=true`

and the caller must be responsible for obtaining it from a trusted SPIFFE provider immediately before prepare.

### If `prepare_for_workload` itself is intended to be the resource/API execution boundary

The current contract is too weak. A compromised/incorrect caller inside the process can synthesize a matching VERIFIED identity object and bypass execution-time provider provenance.

## Recommended hardening

Preferred minimal direction:

1. For `spiffe_workload` tokens, require trusted provider provenance at PREPARED transition.
2. Do not silently skip the check when `trusted_provider_registry` is provided but `provider_instance` is absent.
3. Prefer an explicit fail-closed mode such as:
   - registry + provider instance mandatory; or
   - ledger receives a provider handle and fetches/verifies current identity itself.
4. If a compatibility downgrade is needed, it must be explicit (`allow_unregistered_execution_identity=true`) and default false.
5. Add negative tests:
   - synthetic matching VERIFIED object + no registry => DENY in strict mode;
   - registry present + provider instance absent => DENY;
   - wrong/unregistered provider instance => DENY;
   - trusted provider + freshly fetched matching identity => PREPARED;
   - rotation-safe certificate fingerprint change with same trusted SPIFFE/agent mapping => PREPARED.

## Current RHE canary

PR #15 already uses the stronger path for PREPARED:
- trusted registry passed;
- exact provider instance passed;
- current identity fetched from that provider.

So the positive canary itself is meaningful.

However, passing PR #15 alone would not prove that weaker product call paths are impossible.

## Gate

`PR15_MERGE=DENY_PENDING_CONTRACT_DECISION`

No product-source change is authorized by this document.

No merge, deploy, AWS, trading or capital effect is authorized.
