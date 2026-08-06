# TRIAXIS v3.29-RC1 — Independent Execution-Head Quorum and Completion Witness

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Physical independence: not established
- Administrative independence: not established
- Real external-provider adapter: not included
- Provider-native immutable idempotency: not established
- External WORM/ledger service: not included
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.28 moved execution freshness outside the execution-ledger database and added
provider-side idempotency. Its post-product boundary showed that a coordinated
rollback of the queue, execution ledger, single head authority and provider
store can make a previously completed stable effect executable again.

v3.29 adds two controls with deliberately different functions:

1. an operator-pinned threshold quorum of independently identified execution-
   ledger head authorities; and
2. a separately persisted external completion witness that ingests signed,
   payload-bound provider outcome receipts.

The head quorum answers **whether the local execution ledger is current**. The
completion witness answers **whether the provider already reserved, completed,
failed uncertainly, or proved no effect for the stable `effect_id`**. Neither
object grants action authority.

The precondition for a mutating external effect becomes:

`valid separate action authority AND exact intent/target/payload/state binding AND signed IN_FLIGHT ledger receipt AND current 2-of-3 ledger-head quorum AND provider state ABSENT or proven NO_EFFECT AND completion-witness state ABSENT or proven NO_EFFECT`

## Execution-ledger head quorum

### Operator-pinned configuration

The quorum configuration binds:

- exact `config_id` and `authority_set_id`;
- exact `ledger_id`;
- threshold of at least two;
- every authority ID, service ID, signer ID, key ID and trust domain;
- a validity window;
- a canonical configuration digest supplied independently to the verifier.

A response contributes at most one vote. Distinctness is required across
`authority_id`, `service_id`, `signer_id`, `key_id` and `trust_domain` for every
member of the threshold set.

### Freshness protocol

The verifier issues one single-use challenge under an ephemeral verifier epoch.
Every authority response must be signed and bind the same:

- ledger and ledger-authority identity;
- verifier identity and epoch;
- challenge digest and request time;
- ledger sequence;
- ledger head-event digest;
- ledger state-root digest;
- signed ledger-head digest.

The verifier groups exact statements. A threshold is accepted only when one
statement has enough distinct configured members. It then compares that
statement to a freshly signed local ledger head. A mismatch is rollback or fork
evidence and blocks execution.

### Quorum failure rules

- Duplicate response replay does not add a vote.
- Duplicate signer, key, authority or service identities do not add a vote.
- A signer producing two different statements for the same challenge is
  equivocation and fails closed.
- One current, one stale and one unavailable authority do not form a quorum.
- Two matching current authorities can outvote one stale authority in a 2-of-3
  configuration.
- Two distinct valid quorums for different statements are contradictory state
  and fail closed.
- A substituted or weakened quorum configuration is rejected by exact digest.
- A signed quorum witness is durable evidence only; it carries
  `authority_granted=false` and is revalidated against the independently pinned
  quorum configuration before handoff.

## External completion witness

The completion witness uses a separate SQLite state domain and Ed25519 identity.
It stores one record per stable `effect_id` and exact provider payload digest.
Its append-only event chain is signed and hash-linked.

State machine:

`ABSENT → RESERVED → UNKNOWN | COMPLETED | NO_EFFECT`

Controlled reconciliation:

`UNKNOWN → COMPLETED | NO_EFFECT`

Controlled retry generation:

`NO_EFFECT → RESERVED`

### Reservation

Before the provider mutation, the witness records:

- stable `effect_id`;
- exact provider payload digest;
- provider and service identity;
- provider request identity;
- generation;
- previous and new witness state.

`RESERVED`, `UNKNOWN` and `COMPLETED` block another external effect. Exact replay
returns the existing state and does not grant permission. A different payload,
provider, service or request binding fails closed.

### Provider outcome receipt

The reference provider can issue a durable signed outcome receipt only for:

- `COMPLETED`;
- `UNKNOWN`;
- `NO_EFFECT`.

The receipt binds:

- provider and service identity;
- stable effect and payload digest;
- generation and provider request ID;
- exact state;
- provider response digest, when present;
- outcome evidence digest, when present;
- outcome tick and receipt validity window.

The completion witness verifies the provider signature, trust purpose, identity,
payload, request, generation, freshness and canonical receipt digest before
changing state. A provider database rollback does not erase the completion
witness record while that witness remains current.

### Fresh witness status

The witness returns a signed, single-use challenge-bound status containing its
current global sequence, head-event digest and canonical state-root digest. Only
`ABSENT` or `NO_EFFECT` can support a retry precondition. `RESERVED`, `UNKNOWN`
and `COMPLETED` block.

The reference also verifies the complete signed event chain from genesis and a
separately signed witness head. Sequence gaps, parent substitution, invalid
state transitions, generation discontinuity or identity drift fail closed.

## Required ordering

1. Persist and claim the local queued input.
2. Reconstruct the stable execution intent and verify exact action, target,
   payload, policy, state, expiry and separate authority bindings.
3. Obtain fresh matching responses from the configured head-authority quorum and
   prove that the local signed ledger head has not rolled back.
4. Reserve and move the stable effect to `IN_FLIGHT` in the execution ledger.
5. Deliver every new signed ledger event to all available head authorities.
6. Obtain a second fresh quorum and prove that the exact `IN_FLIGHT` ledger head
   is externally remembered.
7. Obtain fresh provider and completion-witness status for the same effect and
   payload; continue only if both are `ABSENT` or authoritatively proven
   `NO_EFFECT`.
8. Reserve the effect in the external completion witness before provider
   mutation.
9. Recheck the separate action authorization immediately before submission.
10. Submit stable `effect_id` as provider idempotency key and exact payload as
    the provider request.
11. Persist provider outcome as `COMPLETED`, `UNKNOWN` or `NO_EFFECT`.
12. Issue a signed provider outcome receipt and ingest it into the completion
    witness.
13. Persist the corresponding execution-ledger outcome and re-anchor it through
    the head quorum.
14. Acknowledge the local queue only after durable outcome evidence exists.

## Invariants

1. Queue, execution ledger, each head authority, provider state and completion
   witness are distinct logical persistence domains.
2. A claim, dispatch, attempt, authorization-token or process restart never
   changes stable `effect_id`.
3. The quorum policy is operator-pinned and cannot be weakened by the agent
   requesting execution.
4. A vote is counted only from a configured signer/key/domain tuple.
5. Quorum responses are challenge-bound, epoch-bound, time-bounded and
   single-use.
6. Signer equivocation is an integrity incident, not another vote.
7. The local ledger must exactly match the threshold statement.
8. The exact `IN_FLIGHT` ledger state must reach a current quorum before provider
   mutation.
9. Completion-witness reservation precedes provider mutation.
10. Provider outcome evidence is signed, payload-bound, request-bound and
    generation-bound.
11. Provider and completion witness must both permit before retry.
12. `UNKNOWN` never auto-retries.
13. Only authoritative `NO_EFFECT` can open a later generation.
14. Reset, deletion or reinitialization of a head authority or completion witness
    to restore availability is prohibited.
15. No ledger receipt, head response, quorum witness, provider receipt or
    completion status can expand the action-authority envelope.
16. Missing, stale, unsigned, expired, forked, substituted, contradictory or
    unavailable evidence fails closed.

## Executable closure claim

Under the frozen reference tests:

- a 2-of-3 quorum accepts one exact current statement;
- one stale authority cannot override two matching current authorities;
- one current, one stale and one unavailable authority block;
- duplicate votes, duplicate keys, identity substitution and signer equivocation
  block;
- a current quorum detects a rolled-back local ledger;
- the completion witness blocks a replay after provider completion;
- a rolled-back provider store can permit locally while a current completion
  witness still blocks the duplicate;
- `UNKNOWN` can be reconciled only through signed provider evidence;
- only `NO_EFFECT` opens a new witness generation;
- a signed aggregate quorum witness is accepted only against the exact pinned
  configuration;
- the complete completion-witness event chain and signed head are independently
  verifiable;
- combined preflight requires the ledger receipt, head quorum, provider status
  and completion-witness status together;
- all evidence objects preserve `authority_granted=false`.

## Claim boundary and mandatory post-product test

A v3.29 PASS does not establish production exactly-once execution, physical or
administrative independence, trusted time, KMS/HSM key custody, mTLS, capacity,
availability, independent certification, or behavior of any real external
provider.

The mandatory post-product attack must:

1. complete one stable effect across queue, ledger, three head authorities,
   provider and completion witness;
2. prove that current state blocks a duplicate;
3. roll back queue, ledger and provider while keeping a threshold of head
   authorities and the completion witness current, and prove the duplicate still
   blocks;
4. then roll back the queue, ledger, provider, completion witness and a threshold
   of head authorities to their pre-effect snapshots while leaving one authority
   current;
5. measure whether the rolled-back threshold can attest the old ledger head and
   whether the same effect becomes executable again.

If the last condition succeeds, the result is a confirmed boundary, not a test
failure to hide. The next material control must protect completion evidence and
head freshness outside a single threshold-compromise/rollback domain, such as
independently administered completion-witness quorum, provider-native immutable
idempotency, external append-only/WORM receipts, transparency anchoring,
monotonic hardware/KMS counters or an independently verifiable vendor ledger.
