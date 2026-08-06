# TRIAXIS v3.16-RC1 Release Notes

Adds an external signed and challenge-bound head for verifier-side policy-transparency gossip state.

New implementation:

- `policy_transparency_gossip_head.py`;
- verifier-signed monotonic gossip checkpoints;
- external SQLite Gossip Head Authority;
- exact local-state/head enforcement;
- three JSON Schemas;
- closure trigger and regression tests.

This is a reference implementation, not a production deployment.
