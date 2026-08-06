# TRIAXIS v3.17-RC2 Validation Receipt

RC2 is validation-only. Product logic is the exact v3.17-RC1 source tree.

Validated:

- full historical regression;
- v3.16 single external gossip-head closure;
- v3.17 authority-quorum closure;
- exact tagged detached worktree;
- schema validation;
- post-product threshold boundary.

Boundary retained:

A threshold compromise or coordinated rollback of the configured authorities can produce a stale but cryptographically valid quorum. Physical and administrative independence is not established by local labels.

```text
production_qualified=false
independent_certification=false
physical_multi_admin_conformance=false
can_trade=false
capital_permission=DENY
deploy_permission=DENY
```
