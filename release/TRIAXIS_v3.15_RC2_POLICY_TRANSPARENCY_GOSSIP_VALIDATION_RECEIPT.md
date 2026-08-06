# TRIAXIS v3.15-RC2 Policy Transparency Gossip — Validation Receipt

## Classification

Validation-only Release Candidate. Product source remains identical to v3.15-RC1.

## Product identity

- RC1 product commit: `685046b7817a511daba87984490cbec2dceab982`
- RC1 product tree: `cb943dc563c333a9709f1ecb7d192e3f5fa44cf7`
- RC1 source tree: `6c2e743fe193399d68c24b4ee7694672a732ee3a`
- RC1 tag: `TRIAXIS-v3.15-RC1-POLICY-TRANSPARENCY-GOSSIP`

## Exact-tag validation

- historical/unit tests: 296 / 296 PASS;
- v3.14 floor closure: 5 / 5 PASS;
- v3.15 gossip closure: 4 / 4 PASS;
- exact detached worktree: CLEAN;
- source mutation after RC1: NONE.

## Post-commit boundary

The exact v3.15-RC1 tag was attacked by restoring an older whole gossip database after the verifier had pinned floor v3. The restored database erased those pins and accepted a valid lower floor v2.

Status: `BOUNDARY_CONFIRMED`.

Required external control:

- remote gossip replication;
- or signed external gossip head;
- or transparency-log gossip across independent clients;
- or trusted hardware monotonic state.

No local SQLite-only claim is made against hostile whole-database rollback.

```text
production_qualified=false
independent_certification=false
can_trade=false
capital_permission=DENY
deploy_permission=DENY
```
