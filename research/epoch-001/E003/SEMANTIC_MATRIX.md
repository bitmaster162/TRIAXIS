# E003 — SEMANTIC MATRIX

| Semantic Domain | Rekor / in-toto Support | Representation | Notes |
|:---|:---|:---|:---|
| **Build Integrity** | Full | SLSA Level 1–4 Predicates | Verifies build provenance & config source |
| **Tamper Detection** | Full | Cryptographic Digest Binding | Prevents post-build payload modification |
| **Audit Immutability** | Full | Merkle Tree Append-Only Log | Prevents history deletion or rewrite |
| **Identity Verification** | Full | Cosign / Fulcio OIDC Binding | Binds signatures to keyless identity |
