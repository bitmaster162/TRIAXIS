# TRIAXIS Control Stack v3.6-RC1 — Cryptographic Authenticity

## Status

Release Candidate. Not production-qualified. External execution permission is not implied.

## Material defect closed

v3.5 canonical SHA-256 seals proved content integrity but did not authenticate the named issuer, adapter, approver or gate. An attacker could create new content, name a trusted identity, recompute the digest and pass the digest-only boundary.

## New trust boundary

v3.6 introduces Ed25519 signed contract envelopes and an out-of-band public-key registry.

Every authority-bearing object is verified against:

- exact inner contract digest;
- signing key ID;
- signer identity;
- trust domain;
- authorized key purpose;
- key validity window;
- envelope validity window;
- key revocation state;
- Ed25519 signature.

Covered purposes:

1. `ASSURANCE_ATTESTATION`
2. `STATE_WITNESS`
3. `ACTION_APPROVAL`
4. `POLICY_BUNDLE`
5. `AUTHORIZATION_TOKEN`
6. `EXECUTION_RECEIPT` — envelope primitive available; executor integration remains open.

## Enforcement

`authorize_authenticated_action` requires signed assurance, state, policy and every approval before it can issue an authorization token. The gate token is itself signed. A gate-key mismatch forces the inner token to `DENY`.

`AuthenticatedSQLiteExecutionLedger` accepts only:

- a valid signed ALLOW token;
- a valid signed observed state witness;
- exact token/state binding.

Legacy digest-only APIs remain for historical regression and must not be used as the v3.6 production boundary.

## Invariants

- Canonical digest is integrity, not identity.
- Trusted key enrollment is out-of-band.
- Key purpose is non-transferable.
- Trust domain is bound to the key record.
- Revoked or expired keys fail closed.
- A signed envelope cannot be altered without signature failure.
- The execution ledger never consumes an unsigned or forged authorization token.

## Remaining gaps

- registry rollback and key-rotation epochs;
- root-of-trust distribution;
- KMS/HSM custody;
- threshold signatures;
- trusted time;
- signed execution receipts at a real resource boundary;
- distributed revocation propagation;
- hostile administrator resistance.
