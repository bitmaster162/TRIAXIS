# TRIAXIS MATCHED R4 — AGC044 F — 3-ARM COLLAPSE TEST

Date: 2026-08-12, Asia/Bangkok

## Question

Does the surviving full TRIAXIS/EBRC protocol add task-level value beyond a deliberately minimal baseline consisting of:

`Proposer -> executable verifier -> bounded correction -> deterministic gate -> stop`?

## Frozen design

Fresh task: AtCoder AGC044 F — Name-Preserving Clubs, 2400 points.

Three arms:
1. `D0_DIRECT`
2. `M1_MINIMAL`
3. `T2_TRIAXIS`

M1 and T2 had the same executable verifier class, maximum correction count (2), verifier feedback policy, correctness/constraint pass gate, and gold lock. Exact compute/FLOPs were not equalized because prompt/state bookkeeping lengths differ. All three initial models were frozen before any candidate execution. Gold/editorial remained closed until every arm terminated.

## Results

### D0 Direct

D0 used the lower-bound `K=ceil(log2 N)` and modeled omitted codewords as a fully asymmetric complement. This misses the semantic distinction that duplicate clubs may be permuted among themselves without moving any person. The correct predicate is trivial projection of automorphisms onto people, not full matrix asymmetry.

The official sample `N=4 -> 7` is the first witness: strict asymmetry gives six configurations, while one additional projected-rigid configuration with duplicate/twin club columns is legal.

Final: `D0 = FAIL`.

### M1 Minimal

M1 modeled the incidence matrix modulo row/column permutations and used projected automorphism as the correctness condition. After one common-verifier round it derived lower-bound cases as asymmetric simple bipartite cores, transpose symmetry, neighborhood-complement symmetry, iterative reduction to a small canonical pair, a finite exact table for remaining small cores, and duplicate-club exceptions `N=4,7,8`.

Final: `M1 = PASS`, corrections `1/2`.

### T2 TRIAXIS/EBRC

T2 added explicit epistemic/closure state, bound facts vs unresolved assumptions, strongest countermodel, explicit discriminator/reopen condition, and bounded commitment/stop discipline. After the same verifier evidence its executable algorithm was identical to M1.

Final: `T2 = PASS`, corrections `1/2`.

Incremental over M1: rescues 0, harms 0, algorithmic additions 0.

## Shared executable reduction

For a lower-bound case let `k=ceil(log2 N)` and `t=2^k-N`. The strict distinct-club counting core can be represented by an asymmetric bipartite incidence problem `F(a,b)`.

Two invariances collapse the state:

`F(a,b)=F(b,a)`

and

`F(a,b)=F(a,2^a-b)`.

Repeated swap/complement reduction sends enormous instances to a tiny canonical pair. The finite <=1000 table used by both M1 and T2 is:

- (0,0) -> 1
- (0,1) -> 1
- (1,1) -> 2
- (2,2) -> 2
- (3,3) -> 4
- (3,4) -> 6
- (4,4) -> 36
- (4,5) -> 108
- (4,6) -> 220
- (4,7) -> 334
- (4,8) -> 384
- (5,5) -> 976

Other irreducible cores are zero or >1000 for output purposes. Finite duplicate-club exceptions are `N=4 -> 7`, `N=7 -> 336`, `N=8 -> 384`.

## Pre-gold result

| Arm | Initial/final status | Corrections | Final |
|---|---|---:|---|
| D0 Direct | strict-asymmetry model fails N=4 | 0 | FAIL |
| M1 Minimal | projected-automorphism -> finite core reduction | 1 | PASS |
| T2 TRIAXIS | same computational reduction | 1 | PASS |

Therefore:

`T2_INCREMENTAL_RESCUES_OVER_M1 = 0`

`T2_INCREMENTAL_HARMS_OVER_M1 = 0`

`T2_INCREMENTAL_ALGORITHMIC_VALUE = 0`

## Post-freeze official gold audit

The official editorial independently confirms the shared M1/T2 mechanism: good binary boards; distinct rows and the correct projected column-permutation criterion; transpose invariance; complement invariance; recursive canonical reduction; every irreducible canonical core with k>=6 contributes >1000; only k<=5 small cores need exact tabulation; and the only duplicate-club exceptions relevant below the cutoff are N=4,7,8, with duplicate contributions +1,+2,+0.

One nuance is important. The official solution defines the true minimum club count `G(n)`, which can differ from `ceil(log2 n)`. M1/T2 do not explicitly reconstruct `G(n)` for every such n. This does not change their required output: outside the finite N=4,7,8 exceptions, the cases where the lower-bound K is insufficient already have answer >1000, so `-1` is correct.

## Causal adjudication

This is the strongest direct collapse signal obtained so far. The full surviving TRIAXIS/EBRC arm did not outperform the minimal Proposer+Verifier+Gate arm on this non-ceiling 2400-point task. The shared value came from:

`correct semantic model -> executable falsifier -> finite discriminator -> bounded repair -> gate`

not from additional role/persona machinery or the larger EBRC state scaffold.

R4 therefore favors the simpler countermodel on this surface.

Current state:

`MINIMAL_PROPOSER_VERIFIER_GATE = RETAIN`

`EBRC_EXTRA_STATE_DISCIPLINE_TASK_LIFT_R4 = 0`

`DISTINCT_TRIAXIS_CAUSAL_LIFT = UNRESOLVED_BUT_FURTHER_WEAKENED`

`BROAD_INTELLIGENCE_CLAIM = UNSUPPORTED`

`DEVIL_DEFAULT = OFF`

No claim of universal falsification is allowed: one task; same GPT-5.6 Sol session; latent cross-arm contamination; matched correction/verifier budget rather than exact compute; non-independent; non-confirmatory.

## Next discriminator

Do not make TRIAXIS larger. Replicate this exact frozen 3-arm design across a fresh non-ceiling set, preferably multiple 2400–3000 algorithmic tasks, official ProgramBench hard tasks on a Docker-capable rail, and an external/weak model to remove same-session self-contamination.

Promotion rule: Full TRIAXIS earns retained complexity only if it produces reproducible rescues over M1 that are not offset by harms and cannot be explained by verifier/gate budget. Otherwise collapse the research architecture to the minimal core.

## Governance

Research only. No main write. No merge. No deploy. No production/runtime modification. No trading/capital permission.
