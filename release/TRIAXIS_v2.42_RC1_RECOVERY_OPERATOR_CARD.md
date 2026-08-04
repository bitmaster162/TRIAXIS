# TRIAXIS v2.42-RC1 Recovery — Operator Card

1. Treat a checkpoint/envelope identity as owned by one namespace per database.
2. `checkpoint_store_namespace_replay` means the identity already belongs elsewhere; do not retry under another namespace.
3. Distinct namespaces require distinct authenticated checkpoint chains.
4. Ambiguous v1 migration is a human recovery decision; the store will not select an owner.
5. This is same-database confinement, not cross-database cryptographic scope binding.
