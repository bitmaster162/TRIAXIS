# TRIAXIS v3.28-RC1 — Monotonic Execution Head and Provider Reconciliation

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Physical independence: not established
- Administrative independence: not established
- Real external-provider adapter: not included
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.27 demonstrated that a separately persisted execution ledger blocks replay
caused by rollback of the local dispatch queue, but cannot prove its own
freshness after rollback of the complete ledger database. v3.28 adds two further
independent controls:

1. an external monotonic execution-ledger head authority that remembers the
   highest accepted signed ledger chain outside the ledger database; and
2. a provider-side idempotency and reconciliation contract keyed by the same
   stable `effect_id` and exact provider payload digest.

The external-effect precondition becomes:

`valid action authority AND exact target/payload/state binding AND signed IN_FLIGHT ledger receipt AND current externally anchored ledger head AND provider state ABSENT or proven NO_EFFECT`

No receipt, head response, provider status, or quorum result grants action
authority by itself.

## External monotonic execution-ledger head

The head authority stores, for each accepted `ledger_id`:

- exact ledger authority identity;
- highest accepted global ledger sequence;
- accepted head-event digest;
- deterministic ledger state-root digest;
- original signed ledger head;
- every newly accepted signed ledger event.

An advance is accepted only when every missing signed event is supplied in
sequence and the first new event names the authority's externally remembered
head as its parent. It rejects:

- a lower sequence;
- a different event or state root at the same sequence;
- a sequence gap;
- a parent mismatch;
- a ledger or ledger-authority substitution;
- invalid, expired, untrusted, or purpose-mismatched signatures.

A rolled-back ledger can retain its signing key, but it cannot silently replace
or overtake the externally remembered chain with a conflicting fork.

## Fresh head verification

The verifier creates a single-use challenge under an ephemeral verifier epoch.
The head authority returns a fresh signed response bound to:

- head-authority identity and service;
- exact ledger and ledger-authority identity;
- verifier identity and epoch;
- challenge digest and request time;
- externally remembered sequence, head-event digest, and state-root digest;
- response validity window.

The verifier compares that response to a freshly signed local ledger head. Any
sequence, head-event, or state-root mismatch blocks the action as rollback or
fork evidence. Successful verification consumes the challenge and still returns
`authority_granted=false`.

## Provider-side idempotency contract

The reference provider persists one record per stable `effect_id` and exact
`payload_sha256`.

State machine:

`ABSENT → IN_FLIGHT → COMPLETED | UNKNOWN | NO_EFFECT`

Controlled transition:

`NO_EFFECT → IN_FLIGHT` creates a new generation for the same effect and a new
provider request identity.

Rules:

- `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` block another external effect;
- exact transport replay returns the existing record and does not repeat the
  effect;
- the same `effect_id` with a different payload digest fails closed;
- `UNKNOWN` can become `COMPLETED` or `NO_EFFECT` only through authoritative
  reconciliation bound to the exact provider request;
- only signed, fresh, challenge-bound `ABSENT` or `NO_EFFECT` status can support
  a retry decision;
- provider status is evidence, not action authorization.

The included provider is a deterministic reference model. A real adapter must
prove that registration of the idempotency key and the external vendor action
are atomic or are covered by an equivalent vendor-side exactly-once/idempotency
contract.

## Required ordering

1. Persist and claim the local input.
2. Reconstruct and verify the exact stable execution intent.
3. Obtain a fresh external-head response and prove that the local ledger has not
   rolled back before reservation.
4. Reserve and move the effect to `IN_FLIGHT` in the external execution ledger.
5. Deliver all newly signed ledger events to the external head authority.
6. Obtain another fresh challenge-bound response and prove that the externally
   remembered head equals the exact local `IN_FLIGHT` head.
7. Obtain a fresh provider status for the exact `effect_id` and provider payload.
8. Recheck separate action authority, canonical target, payload, policy, state,
   expiry, and all other TRIAXIS execution bindings.
9. Submit the stable `effect_id` as the provider idempotency key. Proceed only if
   the provider atomically accepts the first generation.
10. Record provider and execution-ledger outcome as `COMPLETED`, `UNKNOWN`, or
    proven `NO_EFFECT`.
11. Only after durable outcome evidence may the local queue acknowledge delivery.

## Invariants

1. Queue, execution ledger, head authority, and provider state are distinct
   logical persistence domains.
2. A new claim, dispatch, attempt, token, process, or transport retry never
   creates a new stable effect identity.
3. The head authority accepts only a contiguous authenticated extension of its
   remembered chain.
4. Same-sequence disagreement is a fork, not an update.
5. A fresh head response is challenge-bound, verifier-epoch-bound, time-bounded,
   and single-use.
6. The exact `IN_FLIGHT` ledger state must be externally anchored before the
   mutating provider operation.
7. Provider idempotency binds both `effect_id` and exact payload digest.
8. `UNKNOWN` never auto-retries.
9. A retry requires authoritative `NO_EFFECT` reconciliation in both provider
   and ledger state, plus a new independent action authorization.
10. Unavailable, stale, unsigned, substituted, expired, gapped, forked, or
    contradictory state fails closed.
11. Resetting an external head or provider record to recover availability is
    prohibited.
12. No evidence object may expand the action-authority envelope.

## Synchronization continuity

The reference ledger event envelope has a finite validity window. Every missing
signed event must reach the external head authority before that envelope expires.
Loss of synchronization continuity is a blocking operational incident. This
release does not authorize bypassing the head authority, reinitializing its
state, accepting an unverifiable gap, or silently extending historical
signatures.

## Closure claim

Under the tested reference contracts:

- rollback of the execution-ledger database is detected by a current external
  head authority;
- a rolled-back ledger cannot overtake the remembered head with a conflicting
  event fork;
- rollback of both the ledger and head-authority databases still cannot repeat a
  completed effect while the provider-side idempotency record remains current;
- exact provider transport retries do not repeat the modeled external effect;
- uncertain provider outcomes block until authoritative reconciliation.

## Boundary

This release does not establish production exactly-once execution if all
relevant state domains are rolled back, deleted, forked, or compromised together.
It also does not prove the behavior of any real cloud, payment, trading, email,
code-deployment, or other external provider.

The post-product adversarial gate must restore the execution ledger, external
head authority, and provider idempotency store to pre-effect snapshots and
measure whether the same effect becomes executable again. The next material
control must address that observed boundary through independently administered
head quorum, provider-native immutable idempotency, external append-only/WORM
receipts, monotonic hardware/KMS counters, or independently verifiable provider
reconciliation.
