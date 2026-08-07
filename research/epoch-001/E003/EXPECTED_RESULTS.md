# E003 — EXPECTED RESULTS

1. All 15 transparency corpus test cases execute deterministically.
2. Valid in-toto Statements with verified Rekor Signed Entry Timestamps (SET) return `ALLOW`.
3. Tampered payloads, invalid signatures, untrusted public keys, malformed predicates, expired timestamps, missing SET proofs, and revoked keys return `DENY`.
4. Network transport failures (`Connection Refused`) yield fail-closed `DENY` (`TRANSPORT/REKOR_UNAVAILABLE`).
