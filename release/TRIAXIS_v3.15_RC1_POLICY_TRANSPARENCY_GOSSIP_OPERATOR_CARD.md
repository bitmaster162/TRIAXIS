# TRIAXIS v3.15-RC1 Operator Card

Use the gossip-enabled floor API for every actionable policy validation.

Block when a previously observed witness:

- reports a lower policy version;
- reports a different digest for the same version;
- changes witness, log, key, trust-domain or policy identity.

Back up and replicate the gossip database outside the client host. Local persistence alone does not resist whole-database rollback by a hostile administrator.
