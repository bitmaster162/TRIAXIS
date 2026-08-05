# TRIAXIS v3.13-RC1 — Policy Head Authority Quorum

## Purpose

v3.12 moves policy freshness outside the client but depends on one external signer. v3.13 requires agreement by a pinned threshold of distinct Policy Head Authorities.

## Quorum conditions

A response counts only when all of the following are distinct and configured:

- authority ID;
- signer ID;
- Ed25519 key ID;
- trust domain.

All counted responses must agree on the exact policy ID, version, SHA-256, verifier ID, verifier epoch, challenge and request time.

## Configuration

`TRIAXIS_POLICY_HEAD_QUORUM_CONFIG_v1` defines:

- exact authority set;
- threshold;
- policy ID;
- operator minimum policy version;
- optional exact minimum policy digest;
- validity window.

The consumer must be provisioned with the exact `config_sha256`. A config supplied by an agent or request is not trusted merely because it is well formed.

## Closed failure classes

- one authority rollback;
- one authority compromise or equivocation;
- duplicate responses from one signer/key;
- authority-set substitution;
- threshold downgrade;
- same-provider trust-domain monoculture pretending to be a quorum;
- split view without a threshold agreement.

## Remaining boundaries

- compromise or coordinated rollback of a threshold of authorities;
- substitution of both the quorum config and its independently provisioned digest pin;
- absence of physical deployment separation in the reference test environment;
- trusted time, HSM custody, TLS/mTLS, transparency gossip and independent certification.

`can_trade=false`, `capital_permission=DENY`, `deploy_permission=DENY`.
