# TRIAXIS v3.5-RC2 Operational Assurance — Validation Receipt

## Release classification

- Specification status: Release Candidate
- Implementation status: Partially implemented
- Analysis status: PASS WITH CONDITIONS
- Production-qualified: NO
- Independent certification: NO
- External execution permission: NOT IMPLIED
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Product identity

- RC1 product commit: `ee1dae92cdb93c02bc5f46405bd79a85fbacea7f`
- RC1 product tree: `75779a120e4ec91463bfefaa4aa22876a8b52807`
- RC1 source tree: `09188da51ebee18b3a987ba9b799de4f33756369`
- RC1 annotated tag: `TRIAXIS-v3.5-RC1-EFFECTIVE-EXPIRY`

## Material correction

A single-use authorization token can no longer outlive any trust basis on
which it depends. Its effective expiry is the minimum of:

- action request expiry;
- exact policy validity;
- exact PASS assurance attestation validity;
- authenticated state-witness validity;
- every required approval expiry.

The token carries the source lifetimes and consumer-side validation recomputes
the exact minimum. The execution ledger validates the token again immediately
before preparing an external side effect.

## Exact validation

- Historical/unit tests: 191 / 191 PASS
- Assurance artifact trigger: 6 / 6 PASS
- Assured action scope trigger: 5 / 5 PASS
- Effective authorization expiry trigger: 5 / 5 PASS
- Fresh post-product consumer expiry trigger: 5 / 5 PASS
- End-to-end operational assurance example: PASS
- Offline local-registry JSON Schema validation: PASS
- Detached exact RC1 worktree: CLEAN

## Validation-only RC2 rule

RC2 adds only post-product validation evidence, release receipts and release
metadata. The `src` tree must remain byte-identical to RC1. The release process
must verify this before packaging.

## Residual boundaries

Not established:

- scientific superiority over a simpler `Primary + external verifier + gate`;
- independent evidence from another implementation lineage;
- production IAM/KMS/PKI integration;
- trusted external time;
- hostile-local-administrator resistance;
- distributed fencing or multi-host consensus;
- safety of live irreversible tool execution.
