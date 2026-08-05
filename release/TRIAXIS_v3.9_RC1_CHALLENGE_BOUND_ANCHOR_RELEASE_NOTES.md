# TRIAXIS v3.9-RC1 Release Notes

v3.9 closes replay of a still-valid external registry witness by requiring a fresh verifier-generated single-use challenge.

Added:

- challenge-bound head-witness contract;
- durable challenge ledger;
- verifier and request-time binding;
- response-age bound;
- replay-safe transactional challenge consumption;
- challenge witness JSON Schema;
- replay closure trigger and regression tests.

The release does not claim protection against rollback of the challenge ledger or equivocation by the anchor service.
