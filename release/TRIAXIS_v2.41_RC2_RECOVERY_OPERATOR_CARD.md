# TRIAXIS v2.41-RC2 Recovery — Operator Card

- Use one explicit namespace per trust chain.
- Persist exact receipt and signed envelope; retain the expected-head anchor separately.
- Use CAS with the exact predecessor checkpoint digest.
- Retry an unknown outcome only with the exact same pair and predecessor.
- Back up SQLite, WAL and SHM coherently while the store is active.
- A database copy is not an anti-rollback authority.
- Treat CAS mismatch as a state-refresh requirement.
- Keep external execution permissions separate and denied unless explicitly granted.
