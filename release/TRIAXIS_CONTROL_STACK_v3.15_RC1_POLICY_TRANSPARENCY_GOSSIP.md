# TRIAXIS v3.15-RC1 — Persistent Policy Transparency Gossip

## Problem closed

v3.14 validates a transparency-witness quorum inside one verifier session. A witness could still sign floor v3 to one verifier and later sign floor v2 to another verifier; without shared state, both sessions could independently accept the statements.

v3.15 adds a persistent verifier-side gossip pin for each cryptographically verified witness.

## Invariants

- each signer is permanently bound to one witness ID, log ID, key, trust domain and policy ID;
- a signer may repeat the exact same floor;
- a signer may advance to a higher policy version;
- a signer may not later report a lower version;
- a signer may not report another digest for an already pinned version;
- invalid signatures and malformed responses are never pinned;
- gossip checks happen before quorum counting and before challenge consumption;
- pins persist across verifier process restart.

## New API

- `SQLitePolicyTransparencyGossipStore`
- `enforce_policy_transparency_floor_quorum_with_gossip`

## Explicit boundary

The reference gossip state is local SQLite. Restoring the entire gossip database can erase learned pins. Closing that boundary requires remote gossip replication, an external signed gossip head, a transparency log, trusted hardware monotonic state, or independently maintained client checkpoints.

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
production_qualified=false
```
