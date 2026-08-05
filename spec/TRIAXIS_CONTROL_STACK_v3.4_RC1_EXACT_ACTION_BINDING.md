# TRIAXIS Control Stack v3.4-RC1 — Exact Assured-Action Binding

## Status

- Specification: Release Candidate
- Implementation: partial deterministic reference
- Production qualified: no
- External side effects: not implied

## Defect closed

v3.3 proved that the referenced Decision Assurance Case and Evidence Report had
passed. It did not prove that the PASS attestation covered the exact action that
was later submitted to the gate. The same attestation could be replayed over a
different payload, tool or target after recomputing the outer action digest.

A second defect allowed an issuer-ID set to discard the required trust-domain
binding.

## Assured Action Request

`assured_action_request_sha256` is the canonical digest of:

- principal and intent;
- subject and object;
- capability;
- tool and execution target;
- payload digest;
- policy ID and sequence;
- authenticated state-witness digest;
- risk class.

It excludes the assurance attestation, later approvals, nonce and gate timing so
that those authorization controls can be applied after assurance without a
circular digest.

## Contract changes

- `TRIAXIS_ASSURANCE_PASS_ATTESTATION_v2` binds the exact assured-action digest.
- `TRIAXIS_ACTION_ASSURANCE_ENVELOPE_v3` carries and recomputes that digest.
- `TRIAXIS_SINGLE_USE_AUTHORIZATION_TOKEN_v2` records the exact digest.
- The trusted assurance registry must be an `issuer_id -> trust_domain` mapping.
  Set-only issuer registries fail closed.

## New invariants

### I25 Exact action assurance

A PASS attestation for action A cannot authorize action B, even when B is
permitted by the same policy.

### I26 Semantic payload binding

Changing principal, intent, subject, object, capability, tool, target, payload,
policy sequence, state witness or risk class changes the assured-action digest.

### I27 Trust-domain preservation

Issuer identity without its expected trust domain is insufficient for trust.

## Explicit residual boundary

The assured-action digest proves exact structural binding. It does not prove
that the Decision Assurance Case semantically reasoned correctly about the
payload. That remains an evidence/evaluator quality problem and must be measured
through TRIAXIS-FAIL-BENCH and independent pilots.
