# TRIAXIS v2.40-RC1 Recovery — Operator Card

1. Use one explicit namespace per independent trust chain.
2. Commit genesis with `expected_previous_head=None`.
3. Commit each successor with the exact prior `checkpoint_sha256`.
4. Treat `checkpoint_store_cas_mismatch` as a fresh-read requirement, not a retry hint.
5. On restart supply an external expected head to `load_guard`.
6. Back up SQLite database, `-wal` and `-shm` coherently when active.
7. Do not treat the database file itself as an anti-rollback anchor.
8. External action authority remains separate and denied by default.
