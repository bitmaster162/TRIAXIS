# TRIAXIS Authority Snapshot Freshness Trigger v2.8 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_SNAPSHOT_FRESHNESS_TRIGGER_v2.8_RECOVERY
CANDIDATE_COMMIT: fc364c61a8d7f8483b29fbb5bb82be3b80be7b29
CANDIDATE_TREE: 303a85faae969cf48fbd1b4f1c45c537fb1e59b7
STATUS: Frozen post-commit trigger
AUTHORED: after the v2.34 product commit and before any snapshot-freshness repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Can an authority analysis at host-controlled tick `T` be accepted using a
signed Trust Snapshot whose own `evaluation_tick` is older than `T`?

## Risk

A snapshot is an observation of roots, attestations and revocations at a
particular trust-state time. Keeping its envelope valid or signing it again
later does not reveal revocations or trust-store changes omitted after that
snapshot time.

## Required invariant

```text
accepted authority analysis
=> bundle.frame.evaluation_tick
 == host trusted_evaluation_tick
 == envelope.snapshot.evaluation_tick
```

A stale snapshot must block before checkpoint commitment as:

```text
BLOCKED_BY_TRUST_SNAPSHOT_STATE
stale_trust_snapshot_state
```

Future snapshot state remains governed by the existing
`future_trust_snapshot_state` failure.

## Cases

```text
4 positive controls
5 stale-snapshot negative oracles
9 total cases
```

The bank covers exact genesis/successor acceptance, future-state and host-time
controls, re-signed stale state, still-valid old envelopes, large time advance,
same-bundle stale clocks and stale successors.
