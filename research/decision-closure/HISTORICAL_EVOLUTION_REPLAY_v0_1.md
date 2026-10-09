# TRIAXIS Historical Evolution Replay v0.1

## Goal

Replay the creation history to locate the **earliest minimal mutation** that produces reproducible value, and determine whether later additions preserve that value, add an orthogonal benefit, add only overhead, or harm weak models.

This is deliberately split into two tracks because TRIAXIS evolved into two different kinds of system:

1. **decision/cognitive semantics** — eligible for equal-task cross-benchmark comparison;
2. **assurance/runtime machinery** — eligible for native historical failure-surface and repository-test replay, not for misuse as a reasoning prompt.

Running v3.32 as a math prompt would be a category error.

## Provenance boundary

Git-verified decision history is available through v2.10. The v2.34 recovery record explicitly states that the intervening v2.11-v2.33 Git objects / complete source history were not physically available and were not reconstructed. Therefore:

`v2.11-v2.33 = UNAVAILABLE_GIT_GAP`

No continuous history is inferred across that gap. v2.34 is treated as a recovered artifact lineage on the verified v2.10 ancestry.

## Cognitive replay breakpoints

Normalized cross-benchmark arms:

- `H00_DIRECT`
- `H01_SELF_CRITIQUE`
- `H02_V23_TRIAXIS_CORE`
- `H03_V25_EVIDENCE_ORIGIN`
- `H04_V27_SEVERITY_DEPENDENCY`
- `H05_V28_INPUT_CONTRACT`
- `H06_V29_SEMANTIC_INGRESS`
- `H07_V210_ROLE_GRAPH`
- `H08_V30_DECISION_ASSURANCE`
- `H09_MVT_PROPOSER_VERIFIER`
- `H10_TRIAXIS_MIN`
- `H11_DECISION_CLOSURE`
- `H12_TRIALECTIC_CLOSURE`
- `H13_EBRC_DUAL_STATE`
- `H14_WMX_EBRC`

These arms are explicitly **normalized mechanism distillations**, not claims of byte-identical historical prompt replay. Historical full prompts differ massively in length and include runtime/security controls irrelevant to external reasoning benchmarks.

## Track A — weak-model external replay

Use one fixed weak model and one fixed external benchmark subject.

Initial benchmark: public UMWP / AbstentionBench bridge, preserving native answerability/reference-answer semantics.

Default screen uses 9 breakpoints:

`H00, H01, H02, H03, H06, H08, H10, H13, H14`

Only if differences appear do we spend the requests for all 15 arms.

Primary native metrics:
- overall final accuracy;
- answerable accuracy;
- unanswerable abstention accuracy;
- overanswer rate.

## Track B — native historical runtime replay

Runtime/state/authorization releases are checked at their historical Git commits with repository-native tests. A local runner creates detached worktrees and performs test discovery without fetching packages or mutating the canonical checkout.

The replay intentionally skips the unavailable v2.11-v2.33 lineage.

## Historical hypothesis

The history itself suggests that the largest mutation pressure repeatedly occurred **before or around reasoning**, at input/context/evidence boundaries:

- malformed structured input;
- semantic/source ingress;
- action routing;
- role/context scope;
- dependency/graph ordering;
- evidence origin/common cause.

That points toward the current EBRC/WMX direction — context/state compression, provenance, explicit decision state, selective discriminator/verifier, bounded correction and stop — rather than simply increasing Devil/Angel debate passes.

This is a hypothesis to test, not a retrospective proof.

## Governance

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
