# TRIAXIS v3.26-RC1 — Durable Dispatch and Provider Provenance

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.26 adopts durable input queue and atomic session-mutation patterns from current agent harnesses, then hardens them for operations that may cause external side effects.

A queued item is not removed merely because dispatch started. Mutating work moves through an explicit state machine:

`QUEUED → CLAIMED → DISPATCHING → DELIVERED | UNKNOWN`

A pre-dispatch failure may return the item to `QUEUED`. A timeout or connection loss after dispatch may not be retried automatically because the external effect may already exist.

## Contracts

- `TRIAXIS_QUEUED_INPUT_v1`
- `TRIAXIS_DISPATCH_CLAIM_v1`
- `TRIAXIS_DISPATCH_TRANSITION_v1`
- `TRIAXIS_PROVIDER_REQUEST_RECEIPT_v1`

## Queue invariants

1. User content and attachments are persisted as immutable references and digests before dispatch.
2. FIFO selection occurs only while the target thread is explicitly idle.
3. Queue order mutation uses optimistic compare-and-swap.
4. `claim_id` and `dispatch_id` are globally single-use within the store.
5. The dispatch id is deterministic over queue item, queued bytes and claim identity.
6. A dispatch begins only after a durable `CLAIMED` record exists.
7. Pre-dispatch failure can requeue; post-dispatch uncertainty becomes `UNKNOWN`.
8. `UNKNOWN` can return to `QUEUED` only with exact `NO_EFFECT` evidence.
9. `COMPLETED` reconciliation moves to `DELIVERED` without redispatch.
10. Every state mutation and its digest-sealed event are committed in one SQLite transaction.
11. Expired `CLAIMED` leases requeue; expired `DISPATCHING` leases become `UNKNOWN`.

## Provider request provenance

Provider request IDs, model IDs, trace IDs and request/response digests are recorded as provenance. They do not grant authority and cannot replace TRIAXIS authorization, policy or execution receipts.

## Boundary

The reference store is local SQLite. Restoring the whole queue database to a pre-dispatch snapshot can erase delivered/unknown history and revive an old queued item. Preventing that requires an external monotonic dispatch head, a separately administered execution ledger, or authoritative idempotency/reconciliation at the external tool boundary.
