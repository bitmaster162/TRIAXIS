# Weak-model lift evidence — 2026-08-10

## Question

What interventions can produce very large relative gains for weaker models, and which of those mechanisms should be tested as part of EBRC / WMX?

## Evidence

### 1. Search / latent-capability extraction can approach an order-of-magnitude relative gain

`Common 7B Language Models Already Possess Strong Math Capabilities` reports LLaMA-2 7B first-answer accuracy of 7.9% on MATH versus 72.0% when selecting the best response from 256 random generations. This is about 9.1x final accuracy, but it is compute-heavy and does not by itself solve the practical selection/verifier problem.

Interpretation: weak models can contain substantially more latent capability than greedy decoding reveals. Search is useful only when candidate selection is grounded.

### 2. Executable external validation produces large practical gains where objective checks exist

`CorrectBench: Automatic Testbench Generation with Functional Self-Correction using LLMs for HDL Design` reports 70.13% overall pass ratio versus 33.33% direct generation; on sequential circuits the method is reported as almost five times the direct method. The correction loop uses functional validation/bug information rather than generic reflection.

Interpretation: external executable falsification is a stronger candidate than unconstrained self-critique.

### 3. Self-refinement can be huge on locally inspectable constraints but nearly zero on some reasoning tasks

`Self-Refine` reports large gains on several generation/constraint tasks, while its mathematical-reasoning improvement is much smaller. This supports conditional refinement: revise when the defect can actually be identified, not by default.

### 4. Small agent systems benefit most from tools and coordinator quality

`Can Small Agent Collaboration Beat a Single Big LLM?` reports tool augmentation as the largest and most consistent gain in its setup; a 4B model with tools can outperform a 32B model without tools. Planner-only reasoning can help, while unrestricted full thinking can destabilize tool orchestration.

Interpretation: put expensive deliberate reasoning in the orchestrator, not every executor.

### 5. Long-horizon weak agents benefit from externalized planning/state/context management

`LUMINA` studies planning, state-tracking and history-pruning oracle interventions. It reports that intervention utility depends on model size/environment and explicitly identifies compact state/history handling as a bottleneck in long-horizon agents.

Interpretation: compact state/evidence ledgers should be an ablation, not an aesthetic preference.

## Current WMX hypothesis

The most plausible high-lift weak-model scaffold is not one prompt. It is:

`compact state -> orchestrator -> selective discriminator/tool -> external verifier -> bounded correction -> zero-VOI stop`

with the EBRC record:

- epistemic state
- bounded commitment now
- minimal witness
- one action-changing countermodel
- material reopen trigger

## Kill rules

- If direct-tools / CoT matches WMX at lower cost: collapse WMX.
- If external verifier feedback is unavailable, do not pretend self-critique is equivalent.
- If tool invocation harms tasks where parametric knowledge was already correct, tighten the evidence-value gate.
- If history pruning drops material state, replace pruning with structured state compression.
- If Trialectic ANGEL/DEVIL does not improve failure detection over a simpler EBRC gate, collapse the adversarial layer.
