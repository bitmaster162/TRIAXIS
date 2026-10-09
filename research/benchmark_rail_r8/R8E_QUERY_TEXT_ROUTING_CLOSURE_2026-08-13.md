# TRIAXIS R8-E — Semantic Router Result and Query-Text Routing Branch Closure

Date: 2026-08-13

## Result

The final admissible query-level challenger for this epoch was an externally motivated semantic embedding + clustering mechanism.

Frozen mechanism:
- same 9,210 train / 4,002 held-out rows;
- official 20-model LLMRouterBench small-model pool;
- 30 semantic clusters;
- top-1 model selection per cluster;
- no test-time fitting;
- no live LLM calls.

This was explicitly a **mechanism emulation**, not an official Avengers/Avengers-Pro reproduction. The official small-model configuration requires an external OpenAI-compatible embedding provider.

## Instrument history

R8-E v1 was `F4_INSTRUMENT_INVALID / UNRUN` because the GitHub runner exhausted disk space while installing the PyTorch sentence-transformers stack.

The repair changed only the execution backend: exact-revision quantized ONNX MiniLM + official mean pooling. Split, pool, 30 clusters and top-1 policy were unchanged.

R8-E v2 completed successfully:

- workflow commit: `50515ae2c0e24897d01138610fe463f1d8427cf5`
- run: `31711731130`
- job: `94486146812`
- embedding: `sentence-transformers/all-MiniLM-L6-v2@1110a243fdf4706b3f48f1d95db1a4f5529b4d41`
- LLMRouterBench archive SHA-256: `b79f8cde1a6f029c2efa663a3a3b6f7748defb22341fe59f328cebef6648c8f1`

## Held-out result

| Arm | Weighted score |
|---|---:|
| Best Single — Qwen3-8B | 63.618% |
| Dataset Router | **67.154%** |
| Semantic Cluster Emulation | 66.729% |
| Instance Oracle | 87.181% |

Semantic minus dataset:

`-0.4248 pp`

Bootstrap 95% CI:

`[-1.2994 pp, +0.4123 pp]`

Decision:

`SEMANTIC_CLUSTER_EMULATION = REJECTED_FOR_PROMOTION_ON_THIS_EPOCH`

This is not verified harm; it is failure to show reproducible incremental lift over the stronger simpler baseline.

## R8-C → R8-E rollup

Four query-level challengers have now failed the same dataset-router baseline:

1. TRIAXIS F0 fingerprint: `-0.75 pp`, CI entirely below zero.
2. TF-IDF 5-NN: `-6.03 pp`, CI entirely below zero.
3. TF-IDF linear: `-9.77 pp`, CI entirely below zero.
4. Semantic clustering: `-0.42 pp`, CI crosses zero.

Survivors: `0 / 4`.

The Oracle remains much higher, so routing opportunity remains real. The failed hypothesis is that increasingly complex **query-text routing** captures it reliably.

## Closure

`QUERY_TEXT_ROUTING = INVESTIGATIVE_CLOSED_ON_EPOCH_2026_08_13_A`

Do not reopen for:
- another handcrafted text feature;
- more clusters chosen after seeing test outcomes;
- post-hoc hyperparameter sweeps on this held-out set;
- a larger query-text classifier added only to escape the null.

Material reopen conditions:
- model-native uncertainty/disagreement;
- tool/environment state;
- measured failure/capability probe;
- repo/test/runtime evidence;
- independently validated materially different routing signal;
- new benchmark/model epoch.

## Architecture consequence

Retain dataset/domain routing as the strong simple routing baseline.

`FULL_TRIAXIS_ROUTER = DENY_PROMOTION`

Next research focus: EvoAgentBench capability transfer / failure-conditioned donor selection, not another router redesign.

## Governance

Research only. Main unchanged. No merge/deploy/production/trading/capital permission.