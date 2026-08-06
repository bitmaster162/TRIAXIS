# TRIAXIS v3.30 external-effect control-plane reference

v3.30 separates these logical state domains:

1. durable local dispatch queue;
2. signed external execution ledger;
3. operator-pinned 2-of-3 execution-ledger head quorum;
4. reference provider idempotency state;
5. operator-pinned 2-of-3 completion-witness quorum;
6. a separately signed logical append-only completion anchor.

The completion quorum applies a blocking-minority veto: a valid configured
witness reporting `RESERVED`, `UNKNOWN` or `COMPLETED` blocks retry even when a
permissive threshold could otherwise be assembled. An omitted or unavailable
minority cannot veto and therefore remains in the explicit claim boundary.

The completion anchor consumes signed provider outcome receipts and preserves a
separate signed event chain, head and challenge-bound status. The included
SQLite implementation is a logical append-only reference only. It is not
physical WORM media, hardware anti-rollback state or independent administration.

No component above grants action authority. A same-host deployment proves only
protocol interoperability and negative-test behavior. It does not establish
physical independence, immutable storage or production exactly-once execution.
