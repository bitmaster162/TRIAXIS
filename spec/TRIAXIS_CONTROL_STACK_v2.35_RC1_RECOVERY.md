# TRIAXIS CONTROL STACK v2.35-RC1 Recovery — Snapshot Freshness Delta

## Status

```text
SPECIFICATION_STATUS: Release Candidate
IMPLEMENTATION_STATUS: Partially implemented — recovered deterministic authority path
BASELINE_EVIDENCE_COMMIT: 964469b1b5d9be81da01d550ca89896cac7351dd
PRODUCTION_QUALIFIED: NO
EXTERNAL_ACTION_PERMISSION: NOT IMPLIED
```

## Trigger

Frozen post-commit protocol v2.8 executed against the committed recovered v2.34
product produced:

```text
4 / 9 PASS
5 / 9 FAIL
positive controls: 4 / 4 PASS
```

All five failures accepted a trust snapshot older than the host-controlled
Analysis Bundle evaluation point.

## Normative invariant

An authority-grade analytical acceptance requires exact equality:

```text
bundle.frame.evaluation_tick
== authority_session.trusted_evaluation_tick
== authenticated_snapshot.evaluation_tick
```

A snapshot older than the host tick returns:

```text
status: BLOCK
primary_reason: BLOCKED_BY_TRUST_SNAPSHOT_STATE
error.code: stale_trust_snapshot_state
```

A snapshot newer than the host tick returns:

```text
status: BLOCK
primary_reason: BLOCKED_BY_TRUST_SNAPSHOT_STATE
error.code: future_trust_snapshot_state
```

Both outcomes are state-neutral.

## Commit-bound defense

The exact comparison occurs twice:

1. after envelope authentication and host/bundle time binding, before analytical
   preparation;
2. inside `ProvenanceTrustStateGuard.accept()` under the mutation lock, before
   checkpoint construction.

The second check prevents direct guard callers or an intervening state path from
bypassing the authority-session preflight.

## Contract lineage

```text
v1, v2, v3: preserved identifiers
active: TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v4
```

## Non-claims

This recovery-lineage patch does not recreate unavailable historical Git
objects, provide a durable/distributed trust store, independently certify the
system, or authorize live external action.
