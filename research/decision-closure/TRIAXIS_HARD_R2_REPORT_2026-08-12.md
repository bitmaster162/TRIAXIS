# TRIAXIS HARD R2 — 2000–2200 POINT CLEAN-ARM REPORT

Date: 2026-08-12, Asia/Bangkok

## Executive result

R2 crossed the previous difficulty ceiling and produced one bounded verifier-driven
full-task scalability rescue on a 2000-point external algorithmic task.

Clean-arm outcomes:

| Task | Difficulty | M0 | T1 | Final |
|---|---:|---|---|---|
| AGC013 F — Two Faced Cards | 2000 | semantically correct but O(Q*N log N), performance fail | one bounded structural correction | PASS |
| AGC004 F — Namori | 2200 | constraint-safe direct solution | not activated | PASS |

R2 clean-arm descriptive vector:
- full-constraint M0: 1/2
- final: 2/2
- full-task rescues: 1
- harms: 0
- confirmatory: false

The rescue is a PERFORMANCE_RESCUE and is deliberately not injected into the historical
V22–V55 claim-grade aggregate, whose prior denominator policy quarantined performance-only
M0 failures.

## Protocol-integrity exclusions

The first R2 selection, AGC008 F and AGC014 F, was invalidated before any claim:
small brute/probes were used after statement exposure but before M0 source freeze.
Those tasks are HARD_SELF_CHALLENGE only and are excluded from the clean causal set.

This was not repaired by relabeling after seeing outcomes; the clean protocol was restarted
with a new task.

## AGC013 F — clean scalability rescue

Prereg:
`AGC013_F_CLEAN_PREREG.json`

M0 source:
`AGC013_F_M0.cpp`

M0 status:
`PERFORMANCE_FAIL_SEMANTICS_VALIDATED`

The direct model correctly reduced the problem to unit-job scheduling / interval demand cover.
Official samples and independent small exact checking supported the semantics, but the
per-query solver was O(N log N), for total O(Q*N log N), and therefore invalid for N,Q<=1e5.

T1 was activated against exactly one defect: scalability.

T1 correction #1:
`AGC013_F_T1_R1.cpp`

The correction derives a global query profile F[t]:
- t is the omitted Y-slot for base cards;
- find the hardest/latest feasible omitted slot T;
- construct one optimal schedule at T;
- couple earlier omitted-slot schedules to T through one displaced token;
- after the first token/base displacement at slot s, the remaining cascade equals the
  already-computed F[s] suffix;
- two segment-tree first-hit predicates locate the displacement;
- descending DP computes every F[t].

Evidence:
- official samples PASS;
- 49,000/49,000 independent random exact checks;
- exhaustive rank-space through M=4:
  - 62,500 idle-profile checks at M=4;
  - 390,625 complete query cases at M=4;
  - 0 mismatches;
- N=100000, Q=100000 native smoke: ~0.09 s, ~14.9 MB RSS;
- final complexity O(N log N + Q log N).

Post-freeze official editorial independently corroborates the central mathematical reduction:
coordinate compression, front baseline, back-flip interval additions, suffix query contribution,
and O(N log N)-class global processing. The implementation route is not copied from the gold.

Final:
`CLAIM_GRADE_FULL_TASK_PASS_WITHIN_R2`
`RESCUE_CLASS=PERFORMANCE_RESCUE`

## AGC004 F — clean direct ceiling at 2200

Prereg:
`AGC004_F_CLEAN_PREREG.json`

M0 source:
`AGC004_F_M0.cpp`

The direct derivation assigns each edge a signed net number of operations z_e and obtains:
`sum_{e incident v} z_e = 1`
for every vertex, minimizing:
`sum_e |z_e|`.

Tree:
unique leaf-elimination flow.

Unicyclic:
remove attached trees, solve
`x_{i-1}+x_i=r_i`
on the cycle.
Odd cycles give a unique parity-gated integer solution.
Even cycles have one free integer and the L1 optimum is attained at a median.

Evidence:
- all official sample groups PASS;
- every connected simple tree/unicyclic graph through N=6:
  5,339 exact BFS graph checks, 0 mismatches;
- 1,750 additional random N<=8 exact BFS graph checks, 0 mismatches;
- N=100000 tree/cycle smoke ~0.01 s; <14 MB observed RSS.

Post-freeze official proof independently uses the same flow/L1 structure:
tree edge flow is fixed by subtree imbalance; the cycle leaves a one-dimensional convex L1
objective, with an odd-cycle parity obstruction.

Final:
`CLAIM_GRADE_M0_PASS_WITHIN_R2`
`T1=NOT_ACTIVATED_CEILING`

Freshness caveat:
current TRIAXIS repository search found no AGC004 F/Namori trace, but the Library history
search returned a 401. Therefore the defensible label is:
`REPO_CLEAN_NOT_PROVEN_LIBRARY_VIRGIN`.

## What R2 says about TRIAXIS

R2 supports a narrow mechanism-level statement:

> Once a strong model has a semantically correct but non-viable candidate, executable
> falsification plus a tightly bounded structural correction can convert a real
> constraint failure into a verified constraint-safe solution.

R2 does NOT establish that the integrated TRIAXIS architecture is superior to a simpler
`Proposer + verifier + deterministic gate` stack.

In fact, the successful AGC013 rescue did not require Devil/Angel persona debate.
The strongest countermodel remains materially alive:
most measured value may come from state/evidence binding, executable falsification,
bounded correction and strict stopping rules rather than a distinct multi-role architecture.

Therefore:
`DEVIL_DEFAULT=OFF`
`TRIAXIS_DISTINCT_CAUSAL_LIFT=UNRESOLVED`
`MECHANISM_LEVEL_VERIFIER_VALUE=SUPPORTED_ON_THIS_R2_SURFACE`
`BROAD_INTELLIGENCE_CLAIM=UNSUPPORTED`

## Next clean discriminator

The highest-value next test is not another easy AtCoder batch.

Priority:
1. a fresh >=2200 task selected and frozen before statement exposure, targeting a true M0 failure;
2. official ProgramBench hard-subset execution on a Docker-capable rail;
3. matched-budget comparison against a deliberately minimal Proposer+Verifier baseline.

ProgramBench remains blocked in the current runtime because there is no Docker-compatible
container engine; no improvised run is reported as an official ProgramBench score.

## Governance

Research only.
No main write.
No merge.
No deploy.
No production/runtime change.
No trading/capital permission.
