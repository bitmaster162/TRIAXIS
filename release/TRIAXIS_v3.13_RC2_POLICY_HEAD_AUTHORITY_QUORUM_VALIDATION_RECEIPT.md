# TRIAXIS v3.13-RC2 Policy Head Authority Quorum — Validation Receipt

## Product identity

- RC1 product commit: `8f8ced978a9a175d1abdea3b9b4ec083a82f9745`
- RC1 product tree: `bb11bdefce6b062034442866246893ec638645a1`
- RC1 source tree: `005b634ea61b21eba672fbafb9d8b33b8fa89ed7`
- RC2 is validation-only; source identity must remain equal to the RC1 source tree.

## Exact-product validation

- complete unit/historical suite: 276/276 PASS;
- v3.12 external-head closure: 6/6 PASS;
- v3.13 authority-quorum closure: 5/5 PASS;
- JSON schema validation: PASS;
- detached annotated-tag worktree: clean.

## Post-product boundary evidence

The exact RC1 product confirms:

1. one rolled-back or compromised authority cannot determine the accepted head under a current 2-of-3 quorum;
2. a threshold of rolled-back authorities can return an older head when the independently maintained minimum policy floor is also stale;
3. an updated independent minimum version/digest blocks that rollback;
4. declared trust-domain labels do not prove physical or administrative independence.

Evidence: `evidence/TRIAXIS_v3.13_POSTCOMMIT_THRESHOLD_AND_PHYSICAL_BOUNDARY.json`.

## Release classification

```text
analysis_status=PASS_WITH_CONDITIONS
implementation_status=REFERENCE_IMPLEMENTATION
production_qualified=false
independent_certification=false
physical_multi_admin_conformance=false
can_trade=false
capital_permission=DENY
deploy_permission=DENY
```

The next meaningful gate is physical multi-administrator deployment, independent minimum-policy anchoring or transparency-log gossip. Another same-host SQLite layer would not close this boundary.
