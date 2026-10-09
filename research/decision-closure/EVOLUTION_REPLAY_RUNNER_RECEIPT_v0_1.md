# Evolution Replay Runner Receipt v0.1

Status: `READY / NOT YET EXTERNALLY RUN`

## Local package

- package: `TRIAXIS_EVOLUTION_REPLAY_v0_1.zip`
- SHA-256: `c7571813c5228ff3ffc0832d7ef848ee4f7ce1373ee83209f836693ba247b301`
- history entries: `52`
- normalized cross-benchmark arms: `15`
- default cheap screen arms: `9`
- package preflight: `PASS`

Weak-model runner subset:

- package: `TRIAXIS_EVOLUTION_UMWP20_WEAK_RUNNER_v0_1.zip`
- SHA-256: `4b2d65828cf6783deaa76975dcab70919e2f1057cfb26075e8428941e2356f13`
- fixed default model: `meta-llama/llama-3.2-3b-instruct:free`
- external task: UMWP20 native answerability/reference semantics
- private oracle remains local and is never included in API prompts

## Default screen

`H00_DIRECT`
`H01_SELF_CRITIQUE`
`H02_V23_TRIAXIS_CORE`
`H03_V25_EVIDENCE_ORIGIN`
`H06_V29_SEMANTIC_INGRESS`
`H08_V30_DECISION_ASSURANCE`
`H10_TRIAXIS_MIN`
`H13_EBRC_DUAL_STATE`
`H14_WMX_EBRC`

The full run adds v2.7 severity/dependency, v2.8 input contract, v2.10 role/graph invariance, MVT proposer-verifier, Decision Closure and Trialectic Closure.

## Provenance handling

- v2.3-v2.10: Git-verified history.
- v2.11-v2.33: `UNAVAILABLE_GIT_GAP` per v2.34 recovery record.
- v2.34+: recovered/verified lineage, evaluated primarily on native assurance/runtime failure surfaces.
- v3.32: terminal local-reference runtime layer; explicitly **not** replayed as a reasoning prompt.

## Native replay

The package includes `RUN_NATIVE_HISTORY_REPLAY.py` for a local Git checkout. It creates detached worktrees at selected historical commits and runs repository test discovery without network access or package installation. Missing commits/dependencies are reported, never auto-repaired.

## Interpretation rule

The experiment searches for the **earliest minimal mutation** that creates reproducible external lift. A later control is not part of the candidate core unless it improves an external metric or closes a distinct native failure surface at acceptable cost.

`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
