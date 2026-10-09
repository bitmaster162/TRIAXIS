# Blind Exoskeleton Self-Test v0.1

Date: 2026-08-10

## Status

`SYNTHETIC_MODEL_GENERATED_BLIND_ORACLE`

This is a self-test on GPT-5.6 Sol. It is not an external benchmark and does not establish a broad intelligence claim.

## Procedure

1. Generate an exact-oracle task set spanning computational and combinatorial failure surfaces.
2. Keep the exact oracle private before answer freeze.
3. Run GPT-5.6 Sol standalone without executable tools.
4. Freeze answers.
5. Reveal only PASS/FAIL, not the correct answers.
6. On frozen failures only, provide executable Python/verifier capability while keeping the oracle hidden.
7. Freeze rescue answers.
8. Score against the hidden exact oracle.

One construction-leaked item from an earlier easy quarry was excluded before claims. The final hard quarry contains 8 clean scored items.

## Result

Standalone:

- `1 / 8 = 12.5%`

Frozen failures:

- modular matrix exponentiation
- long deterministic state replay
- Hamiltonian-cycle optimization
- constrained assignment optimization
- toroidal cellular-automaton replay
- SHA-256 computation
- nonlinear modular recurrence

Executable tool/verifier rescue:

- `7 / 7 = 100%` verified rescue

Combined after rescue:

- `8 / 8 = 100%`
- absolute accuracy lift: `+87.5 pp`
- pass-rate multiplier: `8.0x`
- relative pass-rate improvement: `+700%`

## Interpretation

This is the first clean in-session result showing large **system-level capability amplification** rather than prompt-level stylistic improvement.

The strongest demonstrated component is executable external computation/verification. Two rescues (`TSP`, constrained assignment) were optimization/reasoning failures rather than merely long arithmetic, but the result still does not establish general reasoning lift.

Current evidence therefore favors the architecture:

`MODEL -> STRUCTURED STATE -> SELECTIVE EXECUTABLE DISCRIMINATOR/VERIFIER -> BOUNDED CORRECTION -> STOP`

rather than the claim that `DEVIL/ANGEL` or EBRC prompting alone makes the model more intelligent.

## Claim boundary

Do not claim:

- external benchmark superiority;
- general intelligence amplification;
- causal value for Trialectic / DEVIL;
- causal value for EBRC semantics from this test alone.

Do claim only:

> On a model-generated synthetic exact-oracle blind self-test, adding executable tools/verifiers rescued all 7 frozen GPT-5.6 Sol standalone failures, moving the scored result from 1/8 to 8/8.

## Next falsifier

Repeat the same failure-freeze/rescue protocol on external tasks:

1. GeneBench-Pro public case studies with staged files + deterministic grader.
2. ARC-AGI-3 under the official harness when an ARC API key is available.
3. A static external exact-oracle benchmark where raw assets can be made solver-visible without exposing solutions.

Then ablate:

- verifier only;
- verifier + EBRC;
- verifier + active abstraction / state compression;
- verifier + EBRC + one Trialectic countermodel.
