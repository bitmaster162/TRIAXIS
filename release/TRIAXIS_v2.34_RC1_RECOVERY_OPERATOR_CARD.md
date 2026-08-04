# TRIAXIS v2.34-RC1 Recovery — Operator Card

```text
1. Use AuthorityAnalysisSession v3 for every authority-grade Bundle v5.
2. Create guard, roots, transitions, checkpoint and host time outside request data.
3. Freeze the exact Analysis Bundle and signed envelope before validation.
4. Authenticate the envelope without advancing checkpoint state.
5. Bind bundle evaluation_tick to the host-controlled trusted tick.
6. Validate Bundle v5 against the parsed authenticated envelope snapshot first.
7. Any analysis/trust BLOCK must leave checkpoint byte-equivalent to its prior state.
8. Commit the envelope only after analytical status PASS.
9. Let final guard.accept recheck sequence, parent, time, root and handoff under lock.
10. A race after preparation must block; never force or replay around the guard.
11. Persist only the checkpoint returned after successful final acceptance.
12. Treat invalid_analysis_bundle_materialization as hostile/unsupported input.
13. Prepare-before-commit is not durable cross-process transactionality.
14. External action still requires separate policy, authority and execution gates.
```
