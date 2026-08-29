# GPT-5.6 Sol Failure Quarry v0.1

## Purpose

Stop using ceilinged self-authored tasks to search for cognitive lift. Mine benchmark surfaces where GPT-5.6 Sol is already demonstrably below ceiling, freeze baseline failures, then measure verified rescues from individual scaffold components.

## Priority 1 — ARC-AGI-3

Published OpenAI GPT-5.6 Sol result: **7.78%**.

ARC-AGI-3 is interactive and requires exploration, world-model induction, goal acquisition, planning and execution without natural-language instructions.

A recent external result, **Tycho: Active Abstraction with Programmatic World Models for ARC-AGI-3** (arXiv:2607.28287), reports a system that maintains structured history, constructs executable game-specific world models, verifies them against observed transitions, and decides when to build, repair, use or bypass those models. Under the authors' selected policy, GPT-5.6 Sol completed all 183 levels in the 25-game public set and reached 100 RHAE.

Do **not** report this as a clean `7.78 -> 100` causal comparison: harness, policy, settings, budget and evaluation details differ. Treat it as a strong architecture-level signal that externalized state/model/verifier/orchestration can materially alter performance.

### Rescue arms

- A0 baseline/offical-style agent
- A1 structured history only
- A2 executable world model
- A3 verifier-driven model repair
- A4 active-abstraction gate: BUILD / TEST / REPAIR / USE / BYPASS
- A5 EBRC/WMX
- A6 A5 + conditional Trialectic countermodel

Freeze A0 failures first. Enhanced arms are scored on frozen failures plus a sample of A0 passes for harm detection.

## Priority 2 — GeneBench-Pro

Published GPT-5.6 Sol result: **28.7%** at highest reasoning; **31.5%** with Pro mode on the full benchmark.

OpenAI released 10 public deterministic case studies with staged data files and a reference grader. The benchmark explicitly targets ambiguity, exploratory analysis, artifacts, analysis-path choice, and deciding when results are decision-ready.

Public case IDs:

- multiparent_qtl_hmm_lmm
- statgen_cis_mvmr_winnerscurse_scaling_ldaware
- txr1_mtb_causal_sv
- structural_inversion_subhap_expression_risk
- wf_selection
- hic_sv_masked_loop_strength
- statgen_scrna_ambient_state_eqtl
- carrier_cnv_pseudogene_residual_risk
- crispri_casrx_transcript_vs_locus
- popgen_recent_pulse_sexbias

The public package exposes ground truth for reproducibility, so any solver run must first create a **blind solver view** that strips `ground_truth` and `grader` from solver-visible configs while retaining untouched private configs for grading.

### Rescue arms

- G0 direct
- G1 EBRC
- G2 EBRC + Python verifier/QC
- G3 WMX active analysis
- G4 G3 + conditional Trialectic countermodel

Primary metric: `verified_rescue_rate` on frozen G0 failures. Also report harm on G0 passes and cost/tool calls per rescue.

## Priority 3 — ARC-AGI-2

120 public evaluation tasks with exact grid oracle. Use as a static abstraction control to determine whether gains are specific to interactive state/world-model management or improve generic rule induction.

## Core experimental rule

`BASELINE FAILURE -> FREEZE -> ADD ONE CAPABILITY -> NATIVE VERIFIER -> RESCUE / NO RESCUE / HARM`

Candidate capabilities:

1. compact state/history;
2. evidence/provenance ledger;
3. executable hypothesis/world model;
4. deterministic verifier;
5. active abstraction / value-of-information gate;
6. EBRC commitment/reopen semantics;
7. optional Trialectic countermodel.

## Claim boundary

This quarry does not establish that TRIAXIS/EBRC/WMX improves GPT-5.6 Sol. It identifies benchmark surfaces with sufficient headroom and a preregistered rescue methodology capable of establishing or falsifying such a claim.

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
