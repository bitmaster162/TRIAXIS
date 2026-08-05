# TRIAXIS v3.8-RC1 Operator Card

Before loading operational trust keys:

1. Obtain a head witness from an independent anchor service.
2. Verify its Ed25519 signature through a separately pinned anchor key.
3. Require exact registry ID, sequence and snapshot digest equality.
4. Reject local rollback, local fork, stale anchor or missing local state.

Do not cache an anchor witness beyond its intended freshness window. v3.8 validity timestamps alone are not proof against replay of an old but unexpired witness.
