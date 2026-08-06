# TRIAXIS v3.27-RC1 — External Execution Ledger

## Status

- Specification: Release Candidate
- Implementation: executable reference
- Production-qualified: no
- Physical independence: not established
- Administrative independence: not established
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Purpose

v3.26 proved that restoring the complete local queue database to a pre-dispatch snapshot can revive an already delivered mutating input. v3.27 moves the idempotency decision into a separately persisted execution ledger and introduces a stable effect identity that does not change when the local queue creates a new claim after rollback.

The external call precondition is:

`valid action authority AND exact target/payload/state binding AND signed IN_FLIGHT ledger receipt`

A ledger receipt is necessary but never sufficient authority.

## Stable effect identity

`effect_id` is the canonical digest of:

1. `queue_id`;
2. exact sealed queued-input digest;
3. exact action-envelope digest;
4. exact canonical-target digest.

The execution intent additionally binds the exact authorization-token digest, but that volatile token is deliberately excluded from `effect_id`; rotating or substituting a token therefore cannot create a fresh identity for an already recorded effect. `effect_id` also excludes `claim_id`, `dispatch_id`, `attempt_id`, lease, process identity, provider request ID, local queue version, and transport retry identity.

## Contracts

- `TRIAXIS_EXECUTION_INTENT_v1`
- `TRIAXIS_EXECUTION_LEDGER_EVENT_v1`
- `TRIAXIS_EXECUTION_LEDGER_HEAD_v1`
- existing `TRIAXIS_SIGNED_CONTRACT_ENVELOPE_v1` with purpose `EXECUTION_RECEIPT`

## State machine

`∅ → RESERVED → IN_FLIGHT → COMPLETED | UNKNOWN`

Additional controlled transitions:

- `RESERVED → NO_EFFECT` only when the call did not begin;
- `UNKNOWN → COMPLETED | NO_EFFECT` only with exact authoritative evidence;
- `NO_EFFECT → RESERVED` creates the next generation for the same stable effect.

`RESERVED`, `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` block every new attempt for the same effect. Only a proven `NO_EFFECT` state permits a later generation.

## Invariants

1. The execution ledger is stored outside the local queue database.
2. Every mutating intent is canonical, digest-sealed, and bound to one stable `effect_id`.
3. Every attempt and dispatch identity is globally single-use within the ledger.
4. Exact transport retries return the original signed receipt; conflicting retries fail closed.
5. A new local claim cannot create a new stable effect identity.
6. The external call is gated by a fresh Ed25519-signed `IN_FLIGHT` receipt bound to the exact intent, attempt, and dispatch.
7. Ledger receipts do not grant action authority.
8. Ledger events form one global monotonic sequence and hash chain.
9. The signed ledger head binds the sequence, head event, and deterministic state root.
10. `UNKNOWN` never auto-retries.
11. The ledger records `COMPLETED` before the local queue acknowledges delivery.
12. Unavailable, stale, unsigned, substituted, or conflicting ledger state blocks the mutating call.

## Required ordering

1. Persist and claim the local queued input.
2. Construct the stable execution intent from exact frozen artifacts.
3. Reserve the effect in the external ledger.
4. Move the ledger attempt to `IN_FLIGHT` and verify its signed receipt.
5. Recheck independent TRIAXIS action authority and all action bindings.
6. Perform the external call.
7. Record `COMPLETED` or `UNKNOWN` in the ledger.
8. Only then update the local queue.

## Closure claim

A rollback of the local queue database alone cannot authorize a duplicate effect while the external execution ledger remains current and uncompromised. The revived queue item produces a different `dispatch_id` but the same stable `effect_id`; the ledger returns `BLOCK` for `COMPLETED`, `UNKNOWN`, `IN_FLIGHT`, or `RESERVED` state.

## Boundary

This release does not establish exactly-once execution if the execution-ledger database is also rolled back, deleted, forked, or compromised. Its signed head is useful only when a verifier or anchor outside that rollback domain remembers a newer head. The next material gate is an independently persisted monotonic ledger-head quorum, tool-provider idempotency, or authoritative provider-side reconciliation.
