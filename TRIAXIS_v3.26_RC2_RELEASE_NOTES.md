# TRIAXIS v3.26-RC2 Release Notes

v3.26 adds a durable, side-effect-aware dispatch queue and provider-request provenance.

The queue persists user input and attachment references before dispatch, dispatches only when the target thread is idle, uses compare-and-swap mutations and single-use claim identities, and distinguishes pre-dispatch retryable failure from post-dispatch uncertainty.

A mutating request that may have reached an external system becomes `UNKNOWN`; it is not automatically requeued. Exact `NO_EFFECT` or `COMPLETED` reconciliation is required.

Provider request identifiers are recorded as trace provenance only. They do not grant authority.

RC2 makes no source-code changes. It records the whole-database rollback boundary discovered after the RC1 product commit.
