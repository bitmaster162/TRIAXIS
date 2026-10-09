# False-Closure-16 v0.1

Status: **FROZEN BEFORE SOLVER EXPOSURE**

Purpose: isolate the incremental value of the conditional ANGEL/DEVIL layer by comparing:

- U1 — Decision Closure
- U2 — Trialectic Closure (`REALITY → ANGEL → DEVIL → CLOSURE`)

## Dataset

- 16 cases
- 8 hidden control/trap pairs
- 8 ENOUGH controls
- 8 NOT_ENOUGH false-closure traps
- exact control action-label balance: A1/A2/A3/A4 = 2 each
- exact trap discriminator-label balance: T1/T2/T3/T4 = 2 each
- family and pair metadata hidden
- witness sets require 2–4 observations

Trap families include:
- authority expiry / extension timing
- shared instrument dependency
- reasoning-input provenance dependency
- serving-state currentness scope
- idempotency-domain mismatch
- exact semantic digest binding
- compound causal intervention
- incomplete authoritative retrieval scope

## Primary metrics

- false_closure_resistance
- true_close_accuracy
- trap_discriminator_accuracy

Secondary:
- witness_accuracy
- pair_closure_joint_accuracy
- stop_accuracy

## Frozen survival rule

Trialectic U2 must improve either false-closure resistance or trap-discriminator accuracy by at least **12.5 pp** (one of eight trap cases) with **no loss in true-close accuracy**.

Otherwise there is no evidence from FC16 that the conditional DEVIL layer adds value beyond Decision Closure.

## Validation

Preflight: PASS

Scorer perfect fixture: all metrics 1.0

Scorer bad fixture: false_closure_resistance 0.0, witness 0.0, discriminator 0.0

Scorer validation: PASS

## Artifact hashes

Subject kit SHA-256:
`07ffa196a412c5d3a31efc12524e815218c63dfe631618b542ab36439a8103f5`

Private evaluator SHA-256:
`080a3b6d0b00f65187ab71875ed764f87684c5899bb46b342f9779fb641ff6d5`

The private evaluator/oracle is intentionally not committed.