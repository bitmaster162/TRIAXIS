# TRIAXIS Control Stack v2.34-RC1 Recovery

## Status

```text
SPECIFICATION_STATUS: Release Candidate under self-review
IMPLEMENTATION_STATUS: Partially implemented — deterministic analytical,
authenticated trust-state and prepare-before-commit authority-analysis gates
PRODUCTION_QUALIFIED: NO
EXTERNAL_ACTION_PERMISSION: NOT IMPLIED
V2.33_PRODUCT_COMMIT: 9eb31ef3cba2cee2f8accba0a40789d18da38e69
V2.33_ATOMICITY_TRIGGER_EVIDENCE_COMMIT:
5f61a55a542f2305c9375d8880499ddfbf844c5a
```

The unavailable claimed v2.25 ancestry remains explicitly unreconstructed.
This candidate continues from the verified recovery lineage.

## Trigger

The post-commit protocol
`TRIAXIS_AUTHORITY_ANALYSIS_ATOMICITY_TRIGGER_v2.7_RECOVERY` was authored only
after the exact v2.33 product commit. That commit produced:

```text
4 / 9 PASS
5 / 9 FAIL
positive controls: 4 / 4 PASS
rows canonical SHA-256:
acc16bcadff31f097e888cdab718885d851212fc60d807436c3e9e3875b3e329
```

All five rejected analyses returned `BLOCK`, but the valid signed envelope had
already advanced the monotonic checkpoint. Fresh failures consumed sequence 1;
a rejected successor advanced an existing checkpoint from sequence 1 to 2.

## AuthorityAnalysisSession v3

v2.34 preserves the historical identifiers and makes v3 active:

```text
TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v1  frozen historical surface
TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v2  host-time surface
TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v3  prepare-before-commit surface
```

## Exact input freeze

The authority ingress materializes one immutable working copy of the Analysis
Bundle and one immutable working copy of the signed envelope before making any
material decision.

```text
request Mapping
-> deepcopy(dict(...))
-> one exact bundle value
-> one exact envelope value
```

A bundle Mapping that cannot be materialized blocks without state mutation:

```text
BLOCKED_BY_ANALYSIS_CONTRACT
invalid_analysis_bundle_materialization
```

This prevents request-side mutation from creating a time-of-check/time-of-use
split around checkpoint commitment.

## Prepare-before-commit protocol

The normative sequence is:

```text
1. freeze exact bundle and envelope values;
2. classify authority use from the frozen bundle;
3. authenticate envelope signature/root without changing checkpoint state;
4. bind bundle time to host-controlled evaluation time;
5. validate the exact frozen Bundle v5 against the parsed envelope snapshot;
6. if analysis/trust validation is not PASS, return it and preserve checkpoint;
7. if analysis is PASS, call guard.accept on the exact frozen envelope;
8. guard.accept re-authenticates and atomically rechecks root, expiry, sequence,
   parent, rollback/fork, checkpoint root continuity and configured handoff;
9. only successful accept commits the checkpoint; return the prepared PASS.
```

The prevalidation snapshot is authenticated by the configured envelope root but
does not by itself advance or mint host trust state. The final guard acceptance
is still authoritative for monotonic state.

## State-neutral rejection invariant

```text
ANALYSIS STATUS != PASS
=> checkpoint_after == checkpoint_before
```

This equality includes sequence, envelope and snapshot digests, issuance and
evaluation times, authority/key identity and exact authority-root digest.

For a fresh session, rejection leaves `checkpoint = null`. For a successor,
rejection preserves the exact previously accepted checkpoint.

## Concurrency semantics

Prevalidation does not reserve a sequence. Another caller may legitimately
advance the guard before final acceptance. The final `accept` therefore repeats
all state-sensitive checks under the guard lock. A stale preparation blocks as
a state error; it is never silently committed.

This is optimistic prepare/commit, not a distributed transaction across
processes or durable stores.

## Validation closure

The unchanged frozen v2.7 protocol now produces:

```text
9 / 9 PASS
positive controls: 4 / 4 PASS
rows canonical SHA-256:
05c12354d1142896875be5435b4c2e6a8b9ef5be436b138e8e998660c4241b82
```

Current unit and historical suite:

```text
117 / 117 PASS
```

Earlier subject/context, revocation, rollback, ingress, time, transition and
root-continuity banks remain active.

## Non-claims

v2.34 does not establish:

- a durable transactional checkpoint store;
- cross-process compare-and-swap or distributed consensus;
- exactly-once external action execution;
- resistance to host compromise or malicious trusted configuration;
- independent certification;
- live external execution safety;
- Production qualification.
