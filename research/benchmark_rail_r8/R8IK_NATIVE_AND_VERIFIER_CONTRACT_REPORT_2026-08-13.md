# TRIAXIS R8-I / R8-K — Native Held-Out Result + Verifier Contract Gate

Date: 2026-08-13

## Frozen benchmark contract

- EvoAgentBench runner: `948a17288782d5120778da16b4cf1cad9305d8b4`
- Code split: 182 train / 86 test
- LiveCodeBench evaluator: `28fef95ea8c9f7a547c8329f2cd3d32b92c1fa24`
- incremental v6 shard SHA-256: `bb4c364f71921c4495a6ad15abe1a927350b720009f4933e2e71f8af0f6fd1f5`
- R8-I local B0 freeze SHA-256: `9d65bed2fd80824ab9fd520aa92a13538beec62b4d258c1fdca62c9567f5c0ed`
- workflow run: `31724211667`
- job: `94528434274`

## R8-I native held-out B0

Raw result: 5/6 task PASS.

- `abc392_d`: WA 2/3
- `abc394_a`: PASS 43/43
- `abc394_g`: PASS 41/41
- `abc395_c`: PASS 43/43
- `abc396_b`: PASS 42/42
- `abc397_a`: PASS 43/43

Hidden test contents were not disclosed.

## Instrument adjudication

`abc392_d` is quarantined as `F4_INSTRUMENT_SEMANTIC_MISMATCH`.

Upstream AtCoder accepts absolute/relative error <= 1e-8. The pinned LiveCodeBench standard-input evaluator, after textual mismatch, converts numeric tokens to Decimal and requires exact equality. That is not equivalent to the upstream judge contract.

Therefore:

`VALID_DISCRETE_B0 = 5/5 PASS`

`abc392_d != model failure`

## R8-K train-side contract audit

Four additional EvoAgentBench Code train IDs have confirmed upstream/verifier contract incompatibility under the same generic stdio equality path:

- `abc315_f`: numeric tolerance <= 1e-5
- `abc350_e`: numeric tolerance <= 1e-6
- `abc326_d`: multiple valid constructive grids accepted
- `abc373_g`: multiple valid constructive permutations accepted

Confirmed lower bound only:

- train: 4/182 = 2.20%
- Code overall including `abc392_d`: 5/268 = 1.87%

These are not prevalence estimates; audited cases were not randomly sampled.

## Verifier Contract Gate

Before a benchmark result enters capability memory:

`upstream acceptance contract -> actual benchmark verifier contract -> compatibility gate -> SCORE or QUARANTINE`

Acceptance classes:
- exact text
- exact token sequence
- numeric tolerance
- non-unique constructive
- property validator
- interactive/stateful

If the benchmark verifier cannot represent upstream semantics, the result cannot count as model failure, donor rescue, or harm. Re-admit only with the native checker or a demonstrated equivalent validator.

## Scientific decision

- `EBRC_INSTRUMENT_VALIDITY = REPRODUCED_USEFUL_CONTROL_FUNCTION`
- `COGNITIVE_LIFT_CREDIT = 0`
- `BROAD_LIVECODEBENCH_INVALIDITY_CLAIM = DENY`
- `PINNED_GENERIC_STDIO_CONTRACT_MISMATCH_ON_CONFIRMED_TASKS = YES`

R8-I produced no valid discrete B0 failure after quarantine, so no B1 rescue is claimed.

## R8-J

`abc400_g` was frozen separately before hidden verification and passed 3 official samples, 7,548 exhaustive binary-state instances, 58,842 exhaustive ternary-state instances, and 14,000 randomized small-N cases with zero counterexamples. Native verification remains unresolved because the workflow write was blocked by connector safety status; the block was not bypassed.

## Governance

Research only. No main write, merge, deploy, production/runtime change, or trading/capital permission.
