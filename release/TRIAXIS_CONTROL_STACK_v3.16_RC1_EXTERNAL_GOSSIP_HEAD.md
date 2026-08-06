# TRIAXIS v3.16-RC1 — External Policy Transparency Gossip Head

## Problem closed

v3.15 persisted the highest verified transparency floor inside one verifier-side SQLite gossip database. Restoring that entire database erased the learned pins and allowed an older floor to pass again.

v3.16 exports the exact gossip state, signs it as a verifier checkpoint, installs the checkpoint into an independently persisted monotonic Gossip Head Authority, and requires a fresh challenge-bound authority response before the local gossip state is trusted.

## Trust chain

```text
local witness pins
→ canonical gossip-state root
→ verifier-signed checkpoint
→ external monotonic checkpoint authority
→ fresh challenge-bound signed head
→ exact local-state comparison
```

## Invariants

- a gossip checkpoint is bound to one store, verifier, state root and gossip sequence;
- checkpoint sequence is monotonic and parent-linked;
- an authority accepts an exact retry but rejects rollback, gaps and parent substitution;
- an authority head is bound to a fresh verifier challenge and verifier epoch;
- the local gossip state must exactly match the externally stored checkpoint;
- invalid signatures do not consume the challenge;
- the external authority cannot be replaced by a caller-provided identity.

## Explicit boundary

A single Gossip Head Authority is a remaining independent failure domain. Coordinated rollback of the verifier state and the external authority, or compromise of the authority signing key, can still present a stale head. The next control is an operator-pinned quorum of independently administered Gossip Head Authorities or a public transparency checkpoint.

```text
can_trade=false
capital_permission=DENY
deploy_permission=DENY
production_qualified=false
```
