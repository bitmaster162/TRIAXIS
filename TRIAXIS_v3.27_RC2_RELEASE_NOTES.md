# TRIAXIS v3.27-RC2 Release Notes

v3.27 moves mutating-effect replay protection outside the rollback domain of the local durable-dispatch queue.

A stable `effect_id` binds the persisted queued input, exact action envelope, and canonical target. Volatile claim, dispatch, attempt, provider-request, lease, process, and authorization-token identities cannot create a fresh effect identity. The exact execution intent still binds the authorization-token digest, so token substitution is fail-closed rather than ignored.

The separately persisted ledger records a monotonic signed event chain and signed head. New attempts are blocked while an effect is `RESERVED`, `IN_FLIGHT`, `UNKNOWN`, or `COMPLETED`. Only authoritative `NO_EFFECT` reconciliation permits a subsequent generation.

The ledger receipt is evidence, not action authority. A separate valid authorization remains mandatory.

RC2 makes no product-source changes. It records the post-RC1 whole-ledger rollback boundary: restoring both the queue and execution-ledger databases to pre-dispatch snapshots revives the previously completed effect. Therefore v3.27 does not claim exactly-once execution under rollback or compromise of the ledger itself.
