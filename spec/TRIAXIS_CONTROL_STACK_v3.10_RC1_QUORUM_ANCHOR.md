# TRIAXIS Control Stack v3.10-RC1 — Verifier Epoch and Quorum Anchor

## Status

Release Candidate. Not production-qualified. External execution permission is not implied.

## Defects and external boundaries addressed

v3.9 used a single anchor and a durable single-use challenge ledger. Two boundaries remained:

1. restoring the challenge ledger to pre-consumption bytes could revive an old challenge;
2. one trusted anchor could sign different registry heads for different verifiers.

## Verifier epoch

Each verifier process/session creates a fresh unpredictable epoch token. Only its SHA-256 is disclosed. Challenge rows and anchor witnesses bind to that epoch. The token is not reconstructed from the challenge database.

After restart, restored challenge rows from an old database belong to the previous epoch and fail with `challenge_epoch_mismatch`.

## Distinct-anchor quorum

Operational registry loading requires a threshold of matching signed witnesses from distinct:

- signer identities;
- public keys;
- anchor identities;
- trust domains.

All quorum members must agree on:

- anchor-set ID;
- registry ID;
- sequence and snapshot SHA-256;
- verifier ID and verifier epoch;
- challenge digest and request time.

A single anchor cannot satisfy threshold. Two conflicting threshold groups fail closed with `multiple_anchor_quorums`. Repeated signatures from one signer count once.

## Remaining boundaries

- the caller-provided anchor-authority map and threshold are not yet authenticated or versioned;
- compromise or collusion of a threshold of anchors is not solved;
- trust-domain independence is an administrative claim, not a technical proof of organizational independence;
- process-memory capture can recover the live verifier epoch;
- hostile local-administrator resistance is not established;
- no transparency/gossip protocol or production anchor service is implemented.
