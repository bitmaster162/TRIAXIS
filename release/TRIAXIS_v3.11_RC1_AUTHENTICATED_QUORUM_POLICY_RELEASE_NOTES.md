# TRIAXIS v3.11-RC1 Release Notes

v3.11 removes quorum threshold and membership from untrusted caller configuration.

Added:

- root-signed anchor quorum policy;
- exact signer/key/anchor/domain membership;
- monotonic policy history and head;
- policy-bound quorum member witness;
- managed quorum loader deriving threshold and authorities from current policy;
- schemas, regression tests and closure trigger.

Whole-policy-database rollback and policy-root compromise remain external trust boundaries.
