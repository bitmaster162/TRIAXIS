# TRIAXIS v3.17-RC1 — External Gossip Head Authority Quorum

## Problem closed

v3.16 moved verifier gossip freshness outside the rollback-prone local database, but one external Gossip Head Authority remained a single failure domain. Rolling back that authority together with the client, or compromising its signing key, could present an old checkpoint as current.

v3.17 requires an operator-pinned threshold of distinct external Gossip Head Authorities to return the same exact checkpoint statement under one fresh verifier challenge.

## Quorum identity

Threshold membership is counted only when the responses use distinct:

- authority IDs;
- service IDs;
- signer IDs;
- Ed25519 key IDs;
- declared trust domains.

The exact authority set and threshold are sealed in `TRIAXIS_POLICY_TRANSPARENCY_GOSSIP_HEAD_QUORUM_CONFIG_v1` and supplied with an independently pinned config digest.

## Invariants

- one rolled-back or compromised authority cannot select the accepted head;
- duplicate responses or duplicate keys do not increase quorum weight;
- split views without threshold fail closed;
- a caller cannot silently reduce threshold or replace the authority set under the pinned digest;
- the accepted quorum statement must match the exact verifier-signed checkpoint and exact local gossip state;
- challenge consumption occurs only after quorum, checkpoint and local-state validation.

## Explicit boundary

A threshold compromise or coordinated rollback of the configured authorities remains outside the local reference claim. Declared trust-domain strings do not prove separate machines, operators, providers, jurisdictions or KMS roots. Closing that boundary requires physical multi-admin deployment, an independent minimum gossip checkpoint, public transparency/gossip, or trusted hardware monotonic state.

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
production_qualified=false
```
