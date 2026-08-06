# TRIAXIS v3.14-RC1 Release Notes

Added an independent policy-transparency floor quorum over verified append-only policy histories.

Key changes:

- distinct Ed25519 signing purpose for transparency witnesses;
- challenge-bound minimum-policy floor responses;
- pinned floor-quorum configuration;
- exact binding to Policy Head Quorum configuration;
- verified policy-history containment checks;
- rollback, fork, replay, split-view and equivocation tests;
- two JSON Schemas and a frozen five-case closure trigger.

Historical regression: 288 tests expected to pass before the product commit.
