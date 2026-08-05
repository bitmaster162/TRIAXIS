# TRIAXIS v3.10-RC1 Release Notes

v3.10 adds verifier-session freshness and distinct-anchor quorum validation.

Added:

- ephemeral verifier epoch;
- epoch-bound SQLite challenge ledger;
- quorum-member witness contract;
- threshold agreement by distinct signer, key, anchor and trust domain;
- conflicting-quorum and signer-equivocation rejection;
- quorum witness schema, tests and closure trigger.

The release does not authenticate the supplied anchor-authority map or threshold. Those remain the next policy-integrity boundary.
