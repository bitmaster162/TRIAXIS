# TRIAXIS Control Stack v3.5-RC1 — Effective Authorization Expiry

## Defect closed

v3.4 issued tokens whose expiry followed only the outer action envelope. The
token could therefore remain structurally valid after the policy, assurance
PASS attestation, authenticated state witness or approval used to create it had
expired.

## Rule

For every ALLOW token:

```text
token.expires_at = min(
  action.expires_at,
  policy.valid_until,
  assurance_attestation.valid_until,
  state_witness.valid_until,
  each approval.expires_at
)
```

Null/non-expiring values are excluded; every present finite source participates.
The token records the complete `expiry_sources` projection and its validator
recomputes the minimum.

## Invariants

- **I28 Authority lifetime intersection:** authorization cannot outlive any
  authority or freshness source used to issue it.
- **I29 Consumer-time expiry:** the executor/ledger validates the token at the
  actual preparation tick, not only at issuance.
- **I30 Auditable expiry provenance:** the token identifies which source capped
  its lifetime.

## Status boundary

This closes local temporal composition. Trusted external time, clock rollback
resistance and distributed leases remain unimplemented production requirements.
