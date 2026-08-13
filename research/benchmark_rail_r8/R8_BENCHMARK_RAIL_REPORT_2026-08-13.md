# TRIAXIS R8 — Benchmark Rail E00–E02

Date: 2026-08-13 (Asia/Bangkok)

## Verdict

`E00 = PASS_WITH_DRIFT_QUARANTINE`
`E01_HARNESS = PASS`
`E01_MODEL_REPEATABILITY = BLOCKED`
`E02_RAIL_SMOKE = PASS_NON_CONFIRMATORY`
`EVOAGENTBENCH = PREREGISTERED_NOT_EXECUTED`
`LLMROUTERBENCH = PREREGISTERED_DATA_PINNED_NOT_DOWNLOADED`

No external benchmark lift is claimed.

## E00 — epoch / instrument freeze

TRIAXIS:
- main: `ae280d905c63e4ba0bcadb4633f01a1fb9657920`
- research head before R8: `1b2519143f7b735957fb3cf85b031155e2e0eb38`

EvoAgentBench official public runner:
- commit: `948a17288782d5120778da16b4cf1cad9305d8b4`
- split source revision: `3ac46d860f2f89ff4000f03c9936b618d10570ad`
- official current runner split: 528 train / 267 test across four paper domains
- every domain split SHA is frozen in `E00_EPOCH_FREEZE.json`.

LLMRouterBench:
- code commit: `c77cb0506949d8f959e97967d2fefca0e8ff1b05`
- result archive SHA-256: `b79f8cde1a6f029c2efa663a3a3b6f7748defb22341fe59f328cebef6648c8f1`
- archive size: 1.28 GB.

## E00 drift incident

An older/currently crawled Hugging Face dataset card exposes a previous EvoAgentBench layout
(5 domains / 1006 train / 367 test), while the official public runner released on 2026-08-13 pins
the paper protocol to 4 domains / 528 train / 267 test.

R8 does not reconcile these silently.

Decision:

`AUTHORITATIVE_R8_SPLIT = RUNNER_COMMIT_948a172_SPLIT_MANIFEST`
`OLD_CARD_DENOMINATOR = QUARANTINED`

This is a real Frontier/Dataset Epoch Gate catch.

## Environment probe

- Python 3.13.5
- Node 22.16.0
- Java 21
- Docker absent
- Conda absent
- container DNS unavailable
- independent external model API unavailable in current toolset
- current session reports GPT-5.6 Sol, but no provider-returned API identity exists.

Therefore:
- SWE/Docker claim-grade lanes remain blocked here;
- model repeatability cannot be established by repeated independent Sol API calls;
- same-session self-runs are diagnostic only.

## E01 — deterministic harness repeatability

The frozen deterministic admissibility/gating packet was executed 1,000 times.

Result:

`1000 / 1000 identical`
`unique_decisions = 1`
`unique_hashes = 1`

This validates deterministic controller repeatability only.

It does not validate stochastic/model repeatability.

## E02 — freeze → exact verifier → <=1 correction → fresh verify

A fresh deterministic seed generated 8 exact-computation controls.

B0 was frozen before verifier access.

B0:
- pass: 4/8

B1:
- pass: 8/8
- rescues: 4
- harms: 0
- corrections: 4

Evidence class:

`SAME_SESSION_SELF_DIAGNOSTIC_NON_CONFIRMATORY`

Purpose:
validate the experimental rail and immutable freeze boundary, not claim a new capability result.

## EvoAgentBench prereg

First target: official `code_implementation` / LiveCodeBench release_v6 adapter.

Reason:
- execution-based verifier;
- public 182/86 train/test split;
- no skill logic embedded in evaluator;
- direct test of frozen procedural transfer.

Current execution blockers are recorded, not bypassed.

## LLMRouterBench prereg

Offline path is preferred before current live frontier APIs.

Frozen comparisons:
- Random
- Best Single
- Dataset Oracle
- simple category / nearest-neighbor
- TRIAXIS deterministic fingerprint rules
- Bayesian selector as challenger only
- Oracle.

The 1.28 GB official result archive is pinned by SHA but not downloaded.

No routing result is claimed yet.

## Next admissible action

1. materialize an environment with network + official agent/model endpoint;
2. execute EvoAgentBench Code small smoke under the pinned runner;
3. acquire the pinned LLMRouterBench result archive and run offline simple-router vs TRIAXIS comparisons;
4. only survivors advance to larger/expensive benchmark lanes.

No new TRIAXIS architecture component should be added before those results.
