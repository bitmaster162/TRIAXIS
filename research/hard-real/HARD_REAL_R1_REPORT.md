# TRIAXIS HARD + REAL R1 — SELF/FORENSIC CHALLENGE REPORT

Date: 2026-08-12 (Asia/Bangkok)

## Scope and claim boundary

This package intentionally combines several different evidence classes and keeps them separate:

1. Fresh hard causal screen (self-run): fresh ended-contest tasks selected before statement/gold exposure.
2. Hard self-challenge: a very hard task where the clean M0 split was invalidated before freeze; useful for capability diagnosis only.
3. Historical forensic replay: a real software failure from ContinuityOS, diagnosis frozen before inspecting a later repaired revision.
4. Open-research negative control: a genuine human-unsolved construction problem with deterministic candidate verification.
5. ProgramBench hard lane: task set frozen, but official execution blocked because the current runtime has no Docker-compatible container engine.

None of these self/forensic observations upgrades the existing broad TRIAXIS efficacy claim. `TRIAXIS_IS_ORACLE=false`.

## A. Fresh hard screen — ARC202 C / D

### ARC202 C — Repunits — 900 points

Frozen M0 source SHA-256: `d5f4fd776be2feec65291d5082c0f5afbdf37b18904703b7f80d9d11a7109e98`

Result: **M0 PASS**

Evidence:
- all official samples passed;
- 250/250 random small cases matched an independent exact big-integer LCM oracle;
- no `10^d == 1 (mod 998244353)` for `1 <= d <= 200000`;
- max-scale smoke completed comfortably;
- post-freeze official editorial corroborated the factor-union / divisor structure.

TRIAXIS correction rounds: **0**. Incremental TRIAXIS rescue: **0**.

### ARC202 D — King — 1000 points

Frozen M0 source SHA-256: `93617149df3768f0f44a9020c24edf9e9ecffbba52367f800e0684bc16e8de9a`

Result: **M0 PASS**

Evidence:
- all official samples passed;
- 450/450 random small cases matched direct cell-DP;
- max-scale smoke at `H=W=T=300000` completed locally in about 1.58 s and ~34 MB RSS;
- post-freeze official editorial independently corroborated the top-level binomial inversion and row/column independence.

The M0 one-dimensional solver used a different route from the editorial: tridiagonal determinant generating functions + FPS inversion/convolution.

TRIAXIS correction rounds: **0**. Incremental TRIAXIS rescue: **0**.

Fresh-screen adjudication: `ARC202_C/D = 2/2 M0 PASS`.

This raises task difficulty substantially beyond UMWP20 but still produces a strong-model ceiling. It supplies no causal lift for TRIAXIS.

## B. AGC077 F — Two Types of Tasks — 1800 points

Prereg SHA-256: `3b88e15ce7716ded51814287f21d777865e45f964ed48a3f9f25dfd2ca844cb4`

The Direct/M0 causal comparison was **invalidated** because small brute-force exploration was used after statement exposure but before M0 freeze.

`AGC077_F_M0 = INVALIDATED_PRE_FREEZE_TOOL_EXPLORATION`

No editorial/gold had been seen at that point, so the task remained usable only as a hard self-challenge, not as causal lift evidence.

Frozen stop SHA-256: `844f656c2186edf379a77d4cdec52fbe6f44ded7a2b11d06c952bbf74e288b25`

Final: `T1_PARTIAL_STOP_FAIL`.

Substantial pre-gold structure recovered:
- stable order within each job type;
- conversion to a binary type schedule;
- prefix capacity `U[d] = min(A[d], B[d])`;
- optimal cumulative L path as the pointwise-largest 0/1-increment path bounded by `U`;
- an equivalent formula for the m-th L-task position;
- paired suffix updates under each `R -> L` flip;
- monotone residual-capacity behavior;
- falsification of a simpler one-rotation update model via cascade counterexamples.

Validation:
- corrected static greedy matched 20,160 exhaustive small states;
- prefix-cap/minorant formulation matched 25,200 exhaustive small states;
- additional randomized structural checks supported the m-th-position formula.

Failure: no proved `O(N log N)` (or better) dynamic data structure was obtained within the bounded correction cycle for `N,Q <= 10^6`.

Only after the stop freeze, the official editorial was inspected. Gold uses earliest feasible L-only days `x_i`, free days `y_i` left by latest feasible R-only scheduling, optimal i-th L day `max(x_i,y_i)`, difference process `e_i = #{x_j <= i} - #{y_j <= i}`, answer recovery through `sum |e_i|`, interval +/-1 updates, and same-sign interval maintenance with amortized `O(N log N)` behavior.

Adjudication: `NEAR_MECHANISM_FAIL`.

The pre-gold derivation reached the same static scheduling/capacity/cascade structure, but missed the decisive `e_i + sum|e_i| + sign-interval amortization` compression. This is **not a solve and not a rescue**.

## C. Real software-engineering forensic replay — ContinuityOS

Historical failing revision: `c684484147f9f735b2ab4d858e7c2d8ca965cb01`.
Workflow run: `30659357681`.

Observed:
- clean source: `337 passed, 3 skipped`;
- wheel-only: `1 failed, 320 passed, 3 skipped`;
- portable probes exposed `NameError: ActionSpec` and `NameError: Ledger`.

Frozen pre-fix diagnosis:
1. `WHEEL_ONLY_SCOPE_MISMATCH` — a repository-policy test read `.github/workflows/ci.yml` inside a wheel-only environment where that repository artifact is not part of the installed wheel contract.
2. `LAZY_GLOBAL_INITIALIZATION_ORDER_DEPENDENCY` — legacy gate symbols were injected only by `_ensure_legacy_gate()`, while helper functions used them as if already initialized.
3. `MAIN_PATH_MASKS_HELPER_DEFECT` — normal CLI dispatch performed initialization first; fresh-process direct helper probes did not.
4. Packaging `.github` into the wheel would be a fake fix unless repository metadata were explicitly part of the product contract.

Prereg/diagnosis SHA-256: `aae1c3ed14552facd2b04bafd9c3d4a3adbf0b9be96f64b73c1d8584b9b638e5`.

After diagnosis freeze, a later green revision was inspected. The repaired code introduces `_require_legacy_gate()` and invokes it directly in helper paths including `_paths_from`, `_context`, `_decide`, and `_materialize_rollback`.

Adjudication: `CONTINUITYOS_FORENSIC_REPLAY = DIAGNOSIS_GOLD_MATCH`.

This is meaningful retrospective diagnostic evidence, but **not a fresh blind SWE benchmark**.

## D. Human-unsolved open research — Hadamard order 668

Target: construct a Hadamard matrix of order 668.

Success criterion is deterministic: a candidate `H` with entries +/-1 must satisfy `H H^T = 668 I`.

The current Goethals-Seidel-style cyclic-sequence local-search/annealing method was first forced through known solved warm-up order 428 as a negative control.

Warm-up result: `FAIL — SEARCH_METHOD_INADEQUATE`.

Best preserved nonzero energy reached 448; no verified 428 construction was recovered.

Since the method could not reconstruct known order 428, the 668 search was **not escalated** into a large compute burn.

Adjudication:
- `HADAMARD_428_WARMUP = FAIL`
- `HADAMARD_668 = NOT_LAUNCHED_AFTER_NEGATIVE_CONTROL`
- no “almost solved” claim.

## E. ProgramBench hard lane

Frozen subset: FFmpeg, pandoc, PHP, universal-ctags, cppcheck, DuckDB.

Prereg SHA-256: `6b98e007a16bdb96298f0a12733fa8145751d48c3aca2e6bc68335fea0abd220`.

Current runtime blocker: no Docker / Podman / nerdctl / buildah.

Adjudication: `OFFICIAL_PROGRAMBENCH_RUN = BLOCKED_BY_RUNTIME`.

No improvised clone is reported as an official ProgramBench score.

## Overall R1 adjudication

| Lane | Result | TRIAXIS causal lift? |
|---|---|---|
| ARC202 C 900 | M0 PASS | No — ceiling |
| ARC202 D 1000 | M0 PASS | No — ceiling |
| AGC077 F 1800 | PARTIAL STOP FAIL | Invalid for causal split; near-mechanism only |
| ContinuityOS real CI/runtime failure | DIAGNOSIS GOLD MATCH | Retrospective only |
| Hadamard 428 warm-up -> 668 | Warm-up FAIL; 668 not launched | No |
| ProgramBench hard six | Frozen, runtime blocked | Not run |

## Current conclusion

The easy benchmark ceiling is gone: the 1800-point AGC task stopped the model from producing a complete solution.

What survives is narrower:
- executable falsification and evidence separation remain useful;
- TRIAXIS can improve diagnostic discipline and expose hidden state/scope defects;
- a difficult task can still end in an explicit, correctly bounded FAIL;
- no new broad causal efficacy claim is justified by R1.

The highest-value next clean experiment is an official ProgramBench hard-subset run on a Docker-capable rail, with frozen baseline and TRIAXIS arms under matched budget.
