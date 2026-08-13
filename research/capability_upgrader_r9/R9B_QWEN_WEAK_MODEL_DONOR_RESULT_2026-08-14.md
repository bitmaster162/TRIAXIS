# TRIAXIS R9-B — Qwen3.5-0.8B Weak-Model Targeted Donor Smoke

Date: 2026-08-14 (Asia/Bangkok)

## Frozen contract

- prereg SHA-256: `678741da709023ff69307467566b835abc2b47fed04de9874c1f79a4293919b9`
- source model: `Qwen/Qwen3.5-0.8B`
- source revision: `2fc06364715b967f1860aea9cf38778875588b17`
- backend epoch: `R9B_LLAMA_CPP_BF16`
- llama.cpp: `bdffafa5df64e10cb6eef2f3bba4b4afc5f1c149`
- EvoAgentBench: `948a17288782d5120778da16b4cf1cad9305d8b4`
- LiveCodeBench evaluator: `28fef95ea8c9f7a547c8329f2cd3d32b92c1fa24`
- test6 SHA-256: `bb4c364f71921c4495a6ad15abe1a927350b720009f4933e2e71f8af0f6fd1f5`
- tasks: `abc394_a`, `abc395_c`, `abc394_g`
- decode: greedy, thinking off, max new tokens 768
- no paid model API; no secrets

Arms:
- `W0_DIRECT`
- `W1_GENERIC_CONTROL`
- `W2_TARGETED_CODE_SKILL`

Workflow run: `31732031870`
Job: `94554564170`
Workflow conclusion: `success`

GitHub artifact digests:
- native result: `sha256:b3b44d9000bcc599196a3eaaf612ff803675819aef7dffbba3986e0b41d083d3`
- raw outputs: `sha256:61bc457bae9c8a805996298be046d193d2af03cb83a50ee4c0867a3fdef53723`

## Native held-out result

| Task | W0 direct | W1 generic | W2 targeted |
|---|---|---|---|
| `abc394_a` | PASS 43/43 | WA | WA |
| `abc395_c` | WA | RE | RE |
| `abc394_g` | RE | RE | RE |

Task pass counts:
- W0: `1/3`
- W1: `0/3`
- W2: `0/3`

Primary preregistered W2 vs W1 comparison:
- rescues: `0`
- harms: `0`

Secondary signals:
- W1 vs W0: one direct-pass -> generic-fail harm (`abc394_a`)
- W2 vs W0: one direct-pass -> targeted-fail total-arm harm (`abc394_a`)

## Output audit

The raw-output artifact shows a consistent failure mode on this weak-model/backend epoch:

- `abc394_a`: W0 returned a short code-only solution and passed; W1/W2 changed the task semantics and failed.
- `abc395_c`: W1 and W2 reached the 768-token cap; the generic arm emitted visible analysis despite the instruction not to reveal it, and the targeted arm produced a long/truncated implementation path.
- `abc394_g`: all three arms reached the 768-token cap and failed; additional scaffold did not create a verified rescue.

This supports a bounded interpretation only: additional process/context can consume scarce generation budget and worsen instruction/code-only compliance on a small model. It does not establish a universal anti-scaffolding rule.

## Adjudication

`TARGETED_CODE_SKILL_INCREMENTAL_LIFT = ZERO_ON_R9B`

`TARGETED_CODE_SKILL = DENY_PROMOTION`

`GENERIC_SCAFFOLD = HARM_SIGNAL_ON_1_OF_3_TASKS`

`W0_DIRECT = SURVIVING_SIMPLE_BASELINE`

`R9B_CANDIDATE_POSITIVE = NO`

No R9-C replication of the same targeted donor is justified merely to escape this null. The preregistered promotion condition was not met.

The correct next research move is to follow a materially different measured failure signal or donor mechanism, not add prompt complexity post hoc.

## Claim boundary

- This is exploratory smoke evidence on one exact weak/open model revision and one backend epoch.
- It is independent of the current GPT-5.6 Sol session because inference ran remotely on the frozen Qwen model.
- It is not evidence that targeted skills are universally harmful or useless.
- It is evidence that this specific targeted donor failed to add incremental held-out value over its matched generic control on the frozen R9-B sample.

## Governance

Research only.
No main write.
No merge.
No deploy.
No production/runtime change.
`can_trade=false`.
`capital_permission=DENY`.
