# TRIAXIS v3.17-RC1 Operator Card

1. Pin the exact quorum-config digest outside agent-controlled state.
2. Place each authority in a genuinely distinct failure and administrative domain.
3. Use separate KMS/HSM-backed keys and separate service identities.
4. Issue one fresh verifier challenge to all authorities.
5. Accept only one threshold statement matching the exact checkpoint and local gossip state.
6. Treat threshold-authority compromise or coordinated rollback as unresolved.

`deploy_permission=DENY`
