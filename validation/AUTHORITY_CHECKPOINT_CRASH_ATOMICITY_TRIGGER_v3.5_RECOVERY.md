# TRIAXIS Authority Checkpoint Crash Atomicity Trigger v3.5 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_CHECKPOINT_CRASH_ATOMICITY_TRIGGER_v3.5_RECOVERY
CANDIDATE_COMMIT: 9ef3a3850278a45eddfc15361f0e9955cb746d70
CANDIDATE_TREE: f487f5bec1185077f447e092be389a6d7ea93a59
STATUS: Frozen post-product trigger
AUTHORED: after the v2.41 product commit
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

After abrupt process death at material SQL boundaries, does a clean reopen expose
only the complete old state or the complete new state?

## Crash points

```text
genesis:  after history INSERT, before current INSERT/COMMIT
successor: after history INSERT, before current UPDATE
successor: after current UPDATE, before COMMIT
successor: immediately after COMMIT, before API return
```

## Required outcomes

Before COMMIT, reopen must recover the exact prior head and prior history. After
COMMIT, reopen must recover the exact successor and exact two-row history; retrying
the same successor must reconcile idempotently.

## Scope

This is an executable SQLite/WAL crash-recovery experiment in the current runtime.
It is not a universal proof for all operating systems, filesystems, storage caches,
hardware failures or hostile database rollback.
