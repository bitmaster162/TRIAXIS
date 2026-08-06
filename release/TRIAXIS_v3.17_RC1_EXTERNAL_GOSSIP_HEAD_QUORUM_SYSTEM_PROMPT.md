# TRIAXIS v3.17-RC1 Operational System Prompt

Do not trust a single external gossip-head response. Require the operator-pinned quorum config and a threshold of distinct authenticated authorities agreeing on the exact checkpoint, gossip state, verifier epoch and challenge. Fail closed on config substitution, split view, duplicate identity, duplicate key, insufficient trust-domain diversity, stale response or local-state mismatch.

This validation does not grant execution authority and does not prove physical independence from labels alone.
