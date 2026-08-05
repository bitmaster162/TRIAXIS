# TRIAXIS Research Adjudication Case 001

## Evidence set

| ID | Source | SHA-256 | Use |
|---|---|---|---|
| R1 | `TRIAXIS_AI_Governance_Research_RU.docx` | `22e0035429330a0d0db5ccf7f3936464ced6afbb49e8136724f0e0a19c05a2fe` | Constructive prior-art and vNext design |
| R2 | `TRIAXIS Red Team Architecture Research.docx` | `61753cf4ceb139615a8912b71020b0fc32b9a671e5a31676092c98a5ebaa899a` | Gemini Flash 3.6 red-team |
| R3 | `Red-Team Research TRIAXIS.docx` | `f6e08e9f7960d7a5919bc9c1b4749daf8c165e9f865c04cf8aff1f67e171bc79` | Gemini 3.1 Pro red-team and FAIL-BENCH |
| C1 | `MASTER_SYSTEM_DOSSIER_AND_GEMINI_MEMORY_2026.md.docx` | `1e7be8d7750e06120e8ba3ba030c769e6b81a5720979ef0d22bacf5ade606458` | Restricted integration map only; not imported as public evidence |

The source documents are external research artifacts, not validation receipts for the implementation. Exact numerical claims in the red-team reports remain unverified unless backed by a checked primary source.

## Agreed findings

1. Role labels alone do not provide statistical or functional independence.
2. The strongest TRIAXIS property is the boundary between probabilistic reasoning and deterministic authorization/execution.
3. A Falsifier must produce a measurable distinguishing test; prose criticism is insufficient.
4. Load-bearing claims require evidence provenance or an explicit `UNVERIFIED_ASSUMPTION` state.
5. A synthesis component may request narrower authority but may never grant authority.
6. High-risk decisions need a reviewer or verifier with a materially different failure mode.
7. The system requires explicit stopping rules, policy lifecycle, calibration and ablation tests.
8. Novelty is not established for individual components. Potential differentiation lies in the integrated Decision Assurance protocol.

## Material disagreements

| Question | Constructive report | Red-team reports | Adjudication |
|---|---|---|---|
| Is TRIAXIS novel? | Potential integration novelty | Novelty not established | No scientific/patent novelty claim. Treat integration as a product hypothesis. |
| Do multiple roles improve truth? | Possible with independent evidence | Same-model roles create Agent Theatre | Require independence metadata and ablation evidence. |
| Is Devil a safety veto? | Useful adversarial branch | May create objection flooding | Devil has no authority. Open decision-blocking defeaters escalate; policy gate decides. |
| Can fixed thresholds be adopted? | Benchmarks proposed | Several exact thresholds proposed | Do not adopt universal thresholds without calibration data. Store project-specific thresholds in policy. |

## Adopted architecture decisions

### MUST ADOPT

- Three planes: Epistemic, Assurance, Authority/Execution.
- Versioned authority envelope fixed before reasoning; downstream stages may only narrow it.
- Typed Decision Assurance Case.
- Evidence records with content digest and source correlation group.
- Explicit defeater states and preservation of unresolved decision-blocking defeaters.
- Measurable Falsification Contract.
- Independence classification that does not count role names as independence.
- External verifier requirement for A3.
- Heterogeneous independent review for R3/R4; explicit human approval for R4.
- Deterministic gate request that cannot mint its own outcome.
- Complete mediation at the execution boundary as a production requirement.
- Calibration, regression generation and role ablation.

### SHOULD ADOPT

- Blind payload review and context isolation.
- Independent retrieval budgets and source-correlation marking.
- Policy-as-code with shadow rollout, expiry and emergency revocation.
- Decision cockpit showing claims, defeaters, uncertainty and minimal authority request.
- Trajectory-level evaluation and production drift monitoring.
- Signed attestations and durable execution receipts.

### EXPERIMENTAL

- Reliability-weighted memory for role outputs.
- Heterogeneous model routing by task class.
- LLM-generated attack trees, provided they are scored against known defects and false positives.
- Multi-model research court as an evidence-adjudication product.

### REJECT

- Majority vote as evidence.
- One model playing many roles while claiming independent review.
- Synthesizer or LLM judge granting execution permission.
- Universal numerical risk thresholds without empirical calibration.
- Filled assurance graphs treated as proof of truth.
- Automatic promotion of unknowns to safe assumptions.

## Integration with existing ecosystem

- ArchiveOS: content-addressed evidence vault and source manifests.
- ContinuityOS: decision state, checkpoints, replay and durable memory.
- BitEvo: orchestration runtime; no authority expansion.
- HANRI: bounded protocol evolution from reproducible defects.
- Fable 5 Observer: independent assurance reviewer when genuinely isolated.
- State Authority Plane: deterministic policy and state transition authority.
- Return Plane: signed pass records and execution receipts.
- Operator Decision Sprint / AI-Agent Reliability Audit: first commercial surfaces.

## Decision

`SELECT_WITH_CONDITIONS`: integrate the assurance and authority mechanisms now; retain the cognitive roles only as measurable, replaceable branches. No claim that TRIAXIS improves truth or safety is accepted until ablation and live-tool benchmarks beat simpler baselines at comparable cost.
