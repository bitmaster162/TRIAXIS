# TRIAXIS adoption analysis: xai-org/grok-build

## Adopted because materially useful

- explicit agent loop boundaries;
- plan review and diff-before-execution;
- skills/plugins/hooks as composable extension points;
- bounded child contexts and resumable sessions;
- worktree isolation;
- selective MCP inheritance;
- headless and ACP surfaces;
- durable host-owned workflows;
- bounded-memory and bounded-fanout operational patterns;
- sandbox and permission configuration as first-class runtime objects.

## TRIAXIS hardening beyond direct adoption

- all extensions compile to capability contracts;
- managed requirements form non-widenable ceilings;
- no extension can self-authorize;
- every context item needs explicit disclosure and a digest;
- whole-repository/history disclosure is forbidden;
- hooks create sealed receipts;
- side effects remain behind Action Assurance tokens;
- protocol adapters carry no write credentials;
- compatibility claims are explicitly scoped.

## Remaining gaps

1. Content materialization TOCTOU: the manifest digest must be checked against
   the bytes actually loaded immediately before use.
2. Plugin component TOCTOU: a manifest pin must bind every loaded component,
   not only the package-level source digest.
3. Actual ACP interoperability certification.
4. Real sandbox/container escape testing.
5. MCP server identity, attestation and response provenance.
6. Background-task cancellation and compaction crash testing.
7. Large-session bounded-memory benchmarks.
8. Cross-provider/model routing evaluation.
9. External plugin supply-chain transparency.
10. Physical multi-host and multi-admin conformance remains unchanged from
    v3.18.
