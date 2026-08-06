# TRIAXIS v3.16-RC1 Operator Card

1. Keep verifier checkpoint signing key outside the gossip database.
2. Run the Gossip Head Authority in a separate failure domain.
3. Install each new signed gossip checkpoint in exact parent order.
4. For every protected read, issue a fresh challenge and verify the signed external head.
5. Deny when the local state root or gossip sequence differs from the authority head.
6. Do not claim protection against compromise or rollback of the single external authority.

`deploy_permission=DENY`
