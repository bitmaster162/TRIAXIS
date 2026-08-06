# TRIAXIS v3.30-RC1 — Independent Completion-Witness Quorum and Logical WORM Anchor

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Physical independence: not established
- Administrative independence: not established
- Physical WORM storage: not established
- Hardware/KMS anti-rollback: not established
- Real external-provider adapter: not included
- Provider-native immutable idempotency: not established
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.29 replaced a single execution-head authority with a pinned 2-of-3 quorum,
but retained one external completion witness. Its post-product boundary showed
that coordinated rollback of a threshold of execution-head authorities, the
provider and that completion witness can recreate a valid old control-plane
view and revive an already completed stable effect.

v3.30 adds two controls with deliberately separate functions:

1. an operator-pinned threshold quorum of independently identified completion-
   witness authorities; and
2. a separately signed logical append-only completion anchor that consumes
   provider outcome receipts.

The completion-witness quorum answers **what a threshold of configured
completion memories currently reports for the exact effect and payload**. The
completion anchor answers **whether an externally signed provider outcome was
previously appended to a separate event chain**. Neither object grants or
widens action authority.

The reference precondition for a mutating external effect becomes:

`valid separate action authority AND exact intent/target/payload/state binding AND signed IN_FLIGHT ledger receipt AND current execution-head quorum AND provider state ABSENT or proven NO_EFFECT AND completion-witness quorum ABSENT or proven NO_EFFECT AND completion-anchor state ABSENT or proven NO_EFFECT`

## Completion-witness quorum

### Operator-pinned configuration

The configuration binds:

- exact `config_id` and `witness_set_id`;
- provider and provider-service identity;
- threshold of at least two;
- every witness ID, authority ID, service ID, signer ID, key ID and trust domain;
- a validity window;
- a canonical configuration digest supplied independently to the verifier.

A response contributes at most one vote. Threshold members must remain distinct
across witness, authority, service, signer, key and trust-domain identities.
The agent requesting execution cannot add, remove, substitute or weaken
membership.

### Fresh statement

The verifier issues one single-use challenge under an ephemeral verifier epoch.
Every configured status must be signed and bind the same:

- stable `effect_id`;
- exact provider payload digest;
- provider and provider-service identity;
- verifier identity and epoch;
- challenge digest and request time;
- completion state and generation;
- provider request and receipt identities, where present;
- witness sequence, head-event digest and state-root digest.

Exact semantic statements are grouped. A threshold counts only when enough
distinct current configured witnesses agree on the same complete statement.
`ABSENT` and `NO_EFFECT` are not merged into one permissive vote.

### Blocking-minority veto

A valid configured response reporting `RESERVED`, `UNKNOWN` or `COMPLETED`
blocks retry even when two other witnesses report a permissive state. This
prevents a known blocking minority from being laundered by majority voting.

The veto applies only to a valid response actually received and verified.
An unavailable, omitted or partitioned witness cannot veto. That omission risk
remains part of the explicit post-product boundary.

### Quorum failure rules

- Duplicate response replay does not add a vote.
- Duplicate witness, authority, service, signer, key or domain identities do not
  create independence.
- A signer producing different statements for the same challenge is
  equivocation and fails closed.
- Stale or expired responses do not count.
- A substituted config or digest fails closed.
- Mixed `ABSENT` and `NO_EFFECT` statements do not form one quorum.
- A known blocking minority fails closed.
- A signed aggregate quorum witness is evidence only, carries
  `authority_granted=false`, and is revalidated against the pinned config.

## Logical completion WORM anchor

The reference anchor uses a separate SQLite state domain and Ed25519 identity.
It consumes signed provider outcome receipts and preserves a signed, hash-linked
append-only event chain plus materialized current state.

Supported outcome states:

- `UNKNOWN`;
- `COMPLETED`;
- `NO_EFFECT`.

State transitions:

`ABSENT → UNKNOWN | COMPLETED | NO_EFFECT`

Controlled reconciliation:

`UNKNOWN → COMPLETED | NO_EFFECT`

Controlled retry generation:

`NO_EFFECT → UNKNOWN | COMPLETED | NO_EFFECT`

A `COMPLETED` effect cannot receive a different outcome or payload. Exact signed
receipt replay is idempotent and does not append another event.

### Provider receipt binding

Before appending, the anchor verifies:

- provider signature and trust purpose;
- provider and service identity;
- stable effect and exact payload digest;
- generation and provider request ID;
- outcome state;
- provider response digest, when required;
- evidence digest;
- outcome tick, receipt digest and validity window.

Payload substitution, request substitution, generation discontinuity, stale
receipt, invalid signature or identity drift fail closed.

### Anchor event, head and status

Every event binds:

- anchor, authority and service identity;
- provider and service identity;
- sequence and previous-event digest;
- stable effect and payload;
- generation and provider request;
- prior and new state;
- provider receipt, response and evidence digests;
- provider outcome tick and anchor tick.

The anchor can issue:

- a signed head binding sequence, head-event digest and canonical state root;
- a fresh challenge-bound signed effect status binding the same global head and
  state root.

Full-chain verification rejects sequence gaps, parent substitution, invalid
state transitions, generation discontinuity, event-digest mismatch or identity
drift. Status freshness is single-use.

### Meaning of “WORM” in this release

The implementation is a **logical append-only reference**. Its API and state
machine do not expose deletion or rewrite operations, and the event chain makes
ordinary mutation detectable while the current database survives.

It is not physical WORM media. An administrator with filesystem or backup
control can replace the SQLite database with an old snapshot. v3.30 therefore
must not be described as hardware-backed, immutable, independently operated or
rollback-proof.

## Required ordering

1. Persist and claim the local queued input.
2. Reconstruct the stable execution intent and verify action, target, payload,
   policy, state, expiry and separate authority.
3. Prove the local execution ledger current through the pinned execution-head
   quorum.
4. Reserve the stable effect and move it to `IN_FLIGHT` in the execution ledger.
5. Re-anchor the exact `IN_FLIGHT` head through the execution-head quorum.
6. Query provider state for the exact effect and payload.
7. Query the configured completion-witness authorities under one fresh challenge
   and verify the pinned quorum plus blocking-minority rule.
8. Query the completion anchor under a separate fresh challenge.
9. Continue only when provider, completion quorum and anchor each report
   `ABSENT` or authoritative `NO_EFFECT`.
10. Reserve the effect across completion witnesses according to operator policy.
11. Recheck separate action authority immediately before provider submission.
12. Submit the stable `effect_id` as provider idempotency key with the exact
    payload.
13. Persist provider outcome and issue a signed provider outcome receipt.
14. Deliver the signed outcome to available completion witnesses and the
    completion anchor.
15. Persist the corresponding execution-ledger outcome and re-anchor it.
16. Acknowledge the local queue only after durable outcome evidence exists.

## Invariants

1. Queue, execution ledger, execution-head authorities, provider state,
   completion witnesses and completion anchor are distinct logical domains.
2. Claim, dispatch, attempt, token and process identities never alter stable
   `effect_id`.
3. Both quorum policies are operator-pinned outside the executing agent.
4. A threshold vote requires distinct configured identities and trust domains.
5. Responses are signature-, challenge-, epoch-, time-, effect-, payload- and
   provider-bound.
6. Signer equivocation is an integrity incident.
7. A known blocking completion state cannot be outvoted.
8. `UNKNOWN` never auto-retries.
9. Only authoritative `NO_EFFECT` can support another generation.
10. The anchor accepts only signed provider outcome receipts.
11. Exact receipt replay is idempotent; conflicting replay fails closed.
12. Full anchor chain, head and state root remain independently verifiable.
13. Reset or reinitialization of an authority, witness or anchor to restore
    availability is prohibited.
14. No ledger receipt, quorum witness, completion status or anchor evidence can
    expand the action-authority envelope.
15. Missing, stale, unsigned, expired, substituted, contradictory, forked or
    unavailable required evidence fails closed.

## Executable closure claim

Under the frozen reference tests:

- three configured completion witnesses form a 2-of-3 permissive quorum only on
  one exact statement;
- duplicate responses, identity substitution, config substitution and signer
  equivocation block;
- stale responses do not count;
- mixed `ABSENT`/`NO_EFFECT` statements do not launder into agreement;
- a valid blocking minority vetoes two permissive statements;
- the signed aggregate quorum witness verifies only against the exact pinned
  configuration;
- signed provider outcomes append to the logical anchor with exact replay
  idempotency;
- payload substitution and parent-chain substitution block;
- `UNKNOWN` reconciliation and `NO_EFFECT` generation rules are enforced;
- full chain, signed head, state root and fresh single-use status verify;
- current anchor state blocks a completed effect after provider and completion-
  witness threshold rollback;
- the composed guard requires execution evidence, provider state, completion
  quorum and anchor status together;
- four real service processes reproduce quorum, authenticated mutation, secret
  minimization, anchor block and blocking-minority veto;
- every new normative contract validates against Draft 2020-12 JSON Schema;
- every evidence object preserves `authority_granted=false`.

## Claim boundary and mandatory post-product test

A v3.30 PASS does not establish production exactly-once execution, physical or
administrative independence, trusted time, KMS/HSM custody, mTLS, provider-native
immutability, physical WORM storage, capacity, availability or independent
certification.

The mandatory post-product probe must coordinate snapshots and rollback across:

- queue and execution ledger;
- a threshold of execution-head authorities;
- provider idempotency state;
- a threshold of completion-witness authorities;
- the logical completion anchor.

It must preserve at least one current minority authority and determine whether
the rolled-back threshold plus rolled-back anchor can recreate a permissive old
view for the same stable completed effect. The observed result defines the next
material control; no production exactly-once claim is allowed before that probe.
