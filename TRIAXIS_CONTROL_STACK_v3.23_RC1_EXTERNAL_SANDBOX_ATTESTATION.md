# TRIAXIS v3.23-RC1 — External Sandbox Provision Attestation

## Purpose

A canonical provision receipt is tamper-evident but not authenticated. v3.23 adds a purpose-bound Ed25519 attestation by an out-of-band provisioner and binds that signed statement to the exact sandbox receipt and exact subagent request.

## Added contracts

- `TRIAXIS_SANDBOX_PROVISION_ATTESTATION_v1`
- `TRIAXIS_ATTESTED_SUBAGENT_v1`
- signing purpose `SANDBOX_PROVISION_ATTESTATION`

## Invariants

1. Canonical resealing does not create provisioner identity.
2. The attestation binds exact receipt, plan, child session, backend and namespace identifiers.
3. The request binds the exact signed-envelope digest.
4. Revoked, expired, wrong-purpose or wrong-trust-domain keys fail closed.
5. Required isolation features must be explicitly attested.
6. The attestation cannot outlive the underlying provision receipt.

## Claim boundary

This proves that a trusted Ed25519 key signed a precise statement. It does not prove that the provisioner observed the real OS/container state, that the signer key is held in KMS/HSM, or that runtime measurements originate from TPM/TEE measured boot.

`production_qualified=false`
`deploy_permission=DENY`
