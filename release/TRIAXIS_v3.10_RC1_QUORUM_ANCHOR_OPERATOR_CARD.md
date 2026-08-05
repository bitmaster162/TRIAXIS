# TRIAXIS v3.10-RC1 Operator Card

1. Create a new verifier freshness session at process start.
2. Never restore or reconstruct its epoch token from the challenge database.
3. Issue challenges only inside the active epoch.
4. Require a configured quorum of matching witnesses from distinct anchors and trust domains.
5. Reject a single signer, duplicate signer, conflicting signer statements, conflicting quorums, old epoch, stale response, rollback or fork.
6. Consume the challenge only after exact quorum and local-head validation.

The anchor authority map and threshold are security-critical configuration. v3.10 does not yet cryptographically authenticate them.
