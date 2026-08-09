# Core Search GPT-5.6 Sol self-run — 2026-08-10

Status: author-contaminated conformance/ceiling diagnostic. Not valid evidence of protocol lift.

## Arms

- K0 DIRECT
- K1 EVIDENCE
- K2 ORIGIN
- K3 CONTEXT
- K4 COMMITMENT
- K5 VERIFY
- K6 TRIALECTIC

## UMWP20

All seven arms produced identical raw outputs and scored:

- overall final accuracy: 20/20 = 100%
- answerability decision accuracy: 20/20 = 100%
- epistemic-state accuracy: 20/20 = 100%
- answerable accuracy: 10/10 = 100%
- unanswerable abstention accuracy: 10/10 = 100%
- overanswer on unanswerable: 0%
- false abstain on answerable: 0%

Verdict: `CEILING_ON_GPT56SOL_SELF_RUN`.

UMWP20 remains useful for the fixed weak-model external run, but it cannot attribute Core Search component value on GPT-5.6 Sol in this self-run.

## Dual-State Integrity-16

All seven arms again produced identical raw outputs and scored:

- epistemic accuracy: 16/16 = 100%
- closure accuracy: 16/16 = 100%
- action accuracy: 16/16 = 100%
- witness accuracy: 16/16 = 100%
- reopen accuracy: 16/16 = 100%
- unresolved-closure accuracy: 100%
- semantic-conflation rate: 0%
- pair integrity: 8/8 = 100%

Verdict: `CEILING_ON_GPT56SOL_SELF_RUN`.

## New benchmark-design finding: CONTRACT_TEACHES_MECHANISM

The public DS16 contract explicitly states the key semantic distinction:

`UNRESOLVED does not imply OPEN.`

Therefore K0 DIRECT receives the target mechanism in the task contract itself. DS16 is valid as a conformance test, but it is not a clean causal test of whether K4 COMMITMENT independently teaches or induces that distinction.

### Consequence

For causal ablation, future public tasks must not name the target mechanism or expose its semantic rule. Required behavior should be inferred from neutral task state and measured through metamorphic updates.

## Core Search conclusion from this self-run

Every adjacent delta is zero:

- K1 - K0 = 0
- K2 - K1 = 0
- K3 - K2 = 0
- K4 - K3 = 0
- K5 - K4 = 0
- K6 - K5 = 0

No component can be credited with lift from this run.

Highest-information next tests:

1. fixed weak 3B external evolution screen;
2. mechanism-hidden benchmark where the public output contract does not teach EBRC semantics;
3. verifier-native external tasks (CorrectBench) for K5;
4. causal-study external tasks for K5/K6.
