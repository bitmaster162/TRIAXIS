# External benchmark matrix v0.1

## A. AbstentionBench / UMWP — READY
Native target: answer vs abstain on answerable/unanswerable paired math questions.
Mapping:
- answerable -> epistemic RESOLVED -> ANSWER
- unanswerable -> epistemic UNRESOLVED -> ABSTAIN
Primary metrics: final accuracy, answerability accuracy, overanswer, false abstain.
External bridge artifact: UMWP20 paired subset from the published StandardDataset.

## B. CorrectBench — ADAPTER SPEC READY
Native target: self-correction under intrinsic/external/tool feedback.
Our arms:
- Direct / CoT baseline
- EBRC correction: only revise when a verifier/critique identifies an action-changing defect
- Trialectic EBRC: ANGEL derivation + one DEVIL counterexample, then verifier
- WMX external: deterministic tool/simulator feedback -> bounded correction -> stop

Fair comparison requirement:
Use the same base model, task subset, verifier/tool availability and maximum correction iterations as their baseline methods.

## C. NeuroState-Bench — ADAPTER SPEC READY
Native target: commitment integrity separately from task success, including distractors and side-query probes.
Our mapping:
- task outcome -> action correctness
- commitment integrity -> closure/reopen consistency
- distractor resistance -> irrelevant-update invariance
- side probes -> witness/reopen consistency

Do not change the benchmark tasks or probe labels.

## D. InterveneBench / STRIDES — PLANNED
Native target: causal intervention/study design.
Natural EBRC mapping:
- surviving causal models -> DEVIL countermodel
- study design -> discriminator
- simulation/statistical code -> external verifier
- final design -> bounded commitment

## E. LUMINA — PLANNED
Native target: long-horizon agent failure under planning/state/history interventions.
WMX ablations:
- raw history
- compact evidence/state ledger
- state oracle
- planning oracle
- compact ledger + EBRC tool gate
