# TRIAXIS R8-C — LLMRouterBench Offline Falsification

Date: 2026-08-13

## Decision

`FINGERPRINT_F0 = REJECTED`

The first external offline held-out router probe is a **collapse signal**.

On 4,002 held-out matched rows from 19 datasets in the official 20-model LLMRouterBench small-model pool:

- Best Single (`Qwen3-8B`): **63.62% weighted**
- Dataset-only router: **67.15%**
- TRIAXIS fingerprint F0: **66.40%**
- Instance Oracle: **87.18%**

Increment of F0 over dataset router:

`-0.7496 percentage points`

Bootstrap 95% CI:

`[-1.4868 pp, -0.0375 pp]`

The entire interval is below zero under this exploratory protocol.

## Interpretation

The coarse dataset router gives a real improvement over Best Single.

Adding the frozen query-surface fingerprint:

`length bin + code flag + multiple-choice flag + symbolic/math flag`

**reduces held-out performance**.

Therefore no causal credit is assigned to F0 and it cannot enter capability memory.

The large Oracle gap remains important: routing opportunity exists, but the current fine-grained fingerprint is not the required signal.

## State transition

`FINGERPRINT_F0: DISCOVERY -> REJECTED`

Reason:

`HELDOUT_NEGATIVE_INCREMENT_OVER_SIMPLER_ROUTER`

`DATASET_ROUTER = STRONG_SIMPLE_BASELINE`

`FULL_TRIAXIS_ROUTER = DENY_PROMOTION`

Bayesian and learned routers remain unrun experiments; they are not promoted by the failure of F0.

## Source and freeze

- LLMRouterBench code: `c77cb0506949d8f959e97967d2fefca0e8ff1b05`
- archive SHA-256: `b79f8cde1a6f029c2efa663a3a3b6f7748defb22341fe59f328cebef6648c8f1`
- workflow commit: `dbf384e92d34e2162fc39618c1334a589d98c94f`
- workflow run: `31709613610`
- job: `94478858957`
- train rows: 9,210
- held-out test rows: 4,002
- no live model calls
- no secrets
- test outcomes were not used to choose routes

Evidence class: `EXPLORATORY_OFFLINE_HELDOUT`.

This is not an official LLMRouterBench leaderboard reproduction.

## Next discriminator

Run on the exact same frozen rows:

1. TF-IDF nearest-neighbor within dataset;
2. TF-IDF lightweight supervised classifier;
3. dataset-only router;
4. Best Single;
5. Instance Oracle.

If query-level baselines repeatedly fail to beat dataset routing, collapse routing to coarse domain/dataset selection until a materially better signal is discovered.

No architecture extension is justified by this result.

## Governance

Research only. No main write, merge, deploy, production change, trading or capital permission.