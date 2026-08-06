# TRIAXIS v3.31-RC1 — Availability-Closed Completion Control and External Immutable-Anchor Reference

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Physical independence: not established
- Administrative independence: not established
- Physical WORM storage: not established
- Hardware/KMS anti-rollback: not established
- External immutable-object backend: not included
- Real external-provider adapter: not included
- Provider-native immutable idempotency: not established
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.30 introduced a 2-of-3 completion-witness quorum plus a separately signed
logical completion anchor. Its mandatory boundary showed a remaining
availability attack: two rolled-back completion witnesses can recreate an old
permissive threshold when the one current blocking witness is omitted as
"unavailable". If the provider and logical anchor are also rolled back, a
completed stable effect can reappear as executable.

v3.31 adds two controls with deliberately different functions:

1. **availability-closed completion control** for `HIGH` and `CRITICAL` effects,
   requiring one valid fresh response from every operator-pinned completion
   witness; and
2. an **external immutable-anchor reference** that stores signed provider
   outcome receipts as content-addressed write-once files, appends separately
   signed hash-linked events, and exposes a verifier-side monotonic checkpoint.

The availability policy answers **whether every configured completion memory
has been heard from under one fresh challenge**. The immutable anchor answers
**whether exact signed provider outcome evidence was stored under a stable
content identity and whether its observed signed head has moved backward or
forked relative to verifier memory**. Neither object grants or widens action
authority.

The cumulative mutating-effect precondition becomes:

`valid separate action authority AND exact intent/target/payload/state binding AND signed IN_FLIGHT execution-ledger receipt AND current execution-head quorum AND provider state ABSENT or proven NO_EFFECT AND every pinned completion witness reports one identical permissive current statement AND logical completion-anchor state ABSENT or proven NO_EFFECT AND immutable-anchor state ABSENT or proven NO_EFFECT AND immutable-anchor head is not below or forked from verifier checkpoint`

## Availability-closed completion policy

### Operator-pinned policy

`TRIAXIS_COMPLETION_AVAILABILITY_POLICY_v1` binds:

- exact policy identity;
- exact completion-quorum configuration digest;
- risk class `HIGH` or `CRITICAL`;
- mode `ALL_CONFIGURED_REQUIRED`;
- required witness count equal to the full configured set;
- `max_missing=0`;
- mandatory blocking-minority veto;
- a validity window;
- a canonical policy digest supplied independently to the verifier.

A policy with a lower required count, nonzero missing allowance, a different
mode or a substituted quorum digest is not availability-closed and fails.

### Full configured-set requirement

Every configured witness must contribute one signature-valid, challenge-bound,
fresh statement. The observed set must exactly equal the pinned set across:

- witness ID;
- authority ID;
- service ID;
- signer ID;
- key ID;
- trust domain.

Two valid responses in a 2-of-3 policy no longer suffice for high-risk retry.
Missing, stale, invalid, duplicate, substituted or equivocal membership fails
closed.

### Semantic agreement

The full configured set must agree on one complete permissive statement for:

- stable `effect_id`;
- exact payload digest;
- provider and provider-service identity;
- state and generation;
- provider request/receipt evidence, where present;
- verifier identity, epoch and one single-use challenge;
- each witness sequence, head-event digest and state-root digest.

`ABSENT` and `NO_EFFECT` remain distinct states and cannot be pooled into one
permissive vote. Any valid `RESERVED`, `UNKNOWN` or `COMPLETED` statement blocks.
The public verifier accepts only a non-empty unique subset of `ABSENT` and
`NO_EFFECT` as its permissive-state parameter; caller-supplied widening is an
explicit configuration error.

### Availability witness

A successful evaluation creates
`TRIAXIS_COMPLETION_AVAILABILITY_WITNESS_v1`. It records the exact policy,
quorum witness, full member set, effect, payload, state and freshness context.
It can be separately signed and reverified, but always carries
`authority_granted=false`.

## External immutable-anchor reference

### Content-addressed object storage

The reference stores the canonical signed provider-outcome envelope at:

`objects/<first-two-hex>/<content-sha256>.json`

The content digest is the object identity and version identity. Files are
created with `O_CREAT|O_EXCL`; the public service has no overwrite or delete
endpoint. Exact existing bytes are treated as idempotent replay. Existing bytes
under the same object path that differ from the expected content fail closed.

A signed `TRIAXIS_COMPLETION_IMMUTABLE_OBJECT_RECEIPT_v1` binds:

- anchor, authority, service and retention-policy identities;
- provider and provider-service identities;
- stable effect, exact payload and generation;
- provider request, receipt, response and evidence digests;
- outcome and storage ticks;
- content digest, object ID, version ID and object key;
- retention-until tick, legal hold and write-once assertions;
- `authority_granted=false`.

### Signed append-only event chain

Every accepted provider outcome appends a separately signed
`TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_EVENT_v1` that binds sequence,
previous-event digest, object receipt, effect state and retention evidence.

Supported transitions remain:

- `ABSENT → UNKNOWN | COMPLETED | NO_EFFECT`;
- `UNKNOWN → COMPLETED | NO_EFFECT` for the same generation and provider
  request;
- `NO_EFFECT → UNKNOWN | COMPLETED | NO_EFFECT` in the next generation.

`COMPLETED` cannot be reopened. Exact replay is idempotent and does not append a
second event. Payload, generation, request, content, receipt, parent or identity
substitution fails closed.

### Signed head and challenge-bound status

The anchor issues:

- `TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_HEAD_v1`, binding sequence,
  head-event digest and canonical state root;
- `TRIAXIS_COMPLETION_IMMUTABLE_ANCHOR_STATUS_v1`, binding one effect state to
  the same global head, state root, retention evidence and a fresh single-use
  verifier challenge.

The head and status explicitly state `physical_worm_established=false`.

### Verifier checkpoint

`SQLiteImmutableAnchorCheckpointLedger` stores the highest signed sequence,
head-event digest and state-root digest observed for one anchor identity.

It rejects:

- a lower observed sequence as rollback;
- a different head or state root at the same sequence as fork;
- an anchor identity substitution.

A later higher valid head advances the checkpoint. The checkpoint is verifier
memory only and grants no action authority.

### Meaning of "immutable" in this release

The implementation is an executable **logical immutable-object reference**:
content-addressed files, write-once creation, no overwrite/delete API, signed
append-only events and a monotonic verifier checkpoint.

It is not physical WORM storage. An administrator controlling the filesystem,
backup and verifier checkpoint can restore or delete all of them. v3.31 must not
be described as physically immutable, independently operated, hardware-backed
or production exactly-once.

## Required ordering

1. Persist and claim the local queued input.
2. Reconstruct stable execution intent and verify separate action authority,
   exact target, payload, policy, state and expiry.
3. Establish the current execution-ledger head through its pinned quorum.
4. Reserve the stable effect and move it to `IN_FLIGHT` in the execution ledger.
5. Re-anchor the exact `IN_FLIGHT` head through the execution-head quorum.
6. Query provider state under a fresh challenge.
7. Query **every** configured completion witness under one fresh challenge.
8. Verify the exact availability policy and full configured-set agreement.
9. Query the logical completion anchor under a separate fresh challenge.
10. Query the immutable anchor under a separate fresh challenge and compare its
    signed head with the verifier checkpoint.
11. Continue only when all four outcome domains report `ABSENT` or authoritative
    `NO_EFFECT` and every required witness is present.
12. Reserve completion memory before provider mutation.
13. Recheck separate action authority immediately before submission.
14. Submit stable `effect_id` as provider idempotency key with the exact payload.
15. Persist provider outcome and issue a signed provider outcome receipt.
16. Deliver the receipt to completion witnesses, the logical completion anchor
    and the immutable anchor.
17. Advance verifier checkpoints and persist final execution-ledger outcome.
18. Acknowledge the local queue only after durable outcome evidence exists.

## Invariants

1. Stable `effect_id` is independent of claim, dispatch, attempt, token and
   process identities.
2. Availability policy and both quorum configurations are operator-pinned
   outside the executing agent.
3. High-risk completion control requires the exact full configured witness set.
4. Missing evidence is non-permissive; availability cannot silently weaken
   integrity.
5. A known blocking state cannot be outvoted or hidden through omission.
6. `ABSENT` and `NO_EFFECT` cannot be consensus-laundered into one state.
7. Every response is signature-, identity-, challenge-, epoch-, time-, effect-,
   payload- and provider-bound.
8. The immutable object ID equals the exact canonical content digest.
9. Existing conflicting bytes at a content-addressed path fail closed.
10. Exact receipt replay is idempotent; conflicting replay fails closed.
11. Signed event sequence and parent continuity are mandatory.
12. `UNKNOWN` never auto-retries; only signed `NO_EFFECT` can support another
    generation.
13. A lower anchor checkpoint is rollback; a different same-sequence checkpoint
    is fork.
14. Reset or reinitialization to restore availability is prohibited.
15. No receipt, quorum witness, availability witness, anchor head, checkpoint or
    status can expand action authority.
16. Missing, stale, unsigned, expired, substituted, contradictory, forked or
    rolled-back required evidence fails closed.
17. The caller cannot expand the permissive completion-state set beyond
    `ABSENT` and `NO_EFFECT`.

## Executable closure claim

Under the frozen reference tests:

- all configured completion witnesses are required for the v3.31 policy;
- a missing or stale member blocks even when the old 2-of-3 threshold exists;
- mixed permissive states do not form availability-closed agreement;
- any received blocking member vetoes retry;
- policy weakening, count substitution, membership substitution and permissive
  state-set expansion block;
- the sealed and signed availability witness verifies only against exact pinned
  policy and quorum configuration;
- provider outcomes are written to content-addressed `O_EXCL` objects;
- exact object replay is idempotent without a second event;
- conflicting content, payload, generation, request or parent substitution
  blocks;
- `UNKNOWN` reconciliation and `NO_EFFECT` generation transition are enforced;
- full event chain, signed head, state root and fresh status verify;
- verifier checkpoints detect rollback and same-sequence fork;
- a current immutable `COMPLETED` anchor blocks rolled-back permissive provider
  and completion layers;
- the cumulative guard requires execution evidence, provider state, full
  completion availability, logical anchor and immutable anchor together;
- the real immutable-anchor process enforces mutation authentication, secret
  minimization and content-addressed storage;
- every new normative contract validates against Draft 2020-12 JSON Schema;
- all evidence preserves `authority_granted=false`.

## Claim boundary and mandatory post-product test

A v3.31 PASS does not establish physical or administrative independence,
physical WORM, protected verifier memory, trusted time, KMS/HSM custody, mTLS,
provider-native immutability, production availability, capacity, independent
certification or production exactly-once execution.

The mandatory post-product probe must separately test:

1. rollback of provider and quorum thresholds while one current required
   completion witness remains reachable — availability-closed verification must
   block because old threshold members cannot replace the required current set;
2. rollback of the immutable anchor while verifier checkpoint remains current —
   checkpoint verification must block;
3. coordinated rollback or deletion of provider, all completion witnesses,
   logical anchor, immutable-anchor filesystem and verifier checkpoint — the
   same completed stable effect is expected to become replayable in the local
   reference, defining the next material physical trust boundary.

No physical-immutability or production exactly-once claim is allowed before
that probe is recorded as separate post-product evidence.
