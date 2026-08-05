# TRIAXIS v3.9-RC1 Operator Card

Before loading operational trust keys:

1. Issue a fresh unpredictable challenge from the verifier challenge ledger.
2. Send only that challenge and verifier identity to the independent anchor.
3. Require a signed response bound to the exact challenge digest, verifier, registry head and request time.
4. Reject replay, wrong verifier, expired challenge, old response, rollback, fork, or stale anchor.
5. Consume the challenge exactly once only after all checks and registry materialization pass.

Do not copy or restore the challenge ledger as proof of freshness. Its own rollback resistance remains an open integration boundary.
