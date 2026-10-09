# Spark FC16 external result — 2026-08-10

Source: user-provided Gemini Spark outputs for FC16 U1 and U2.

## Frozen-oracle score

U1 and U2 produced identical 16 decision records.

| Metric | U1 | U2 |
|---|---:|---:|
| overall status accuracy | 15/16 | 15/16 |
| true-close accuracy | 8/8 | 8/8 |
| false-closure resistance | 7/8 | 7/8 |
| witness accuracy | 13/16 | 13/16 |
| trap discriminator accuracy | 7/8 | 7/8 |
| stop accuracy | 15/16 | 15/16 |
| pair closure joint | 5/8 | 5/8 |

`INCREMENTAL_U2_LIFT=0` on this corpus.

## Semantic adjudication

FC16 `status` and `stop` remain invalid for method comparison because the benchmark conflates:

1. epistemic resolution of the underlying world state; and
2. operational closure of a bounded action now.

The external Spark run independently exposed the same defect on `FWS5G6KPN`.

The case directly states that Run B consumed a hidden summary generated from Run A intermediate reasoning. The action surface includes `Do not count them as independent replications`. Spark returned:

`ENOUGH + A2 + stop=true`

while the frozen oracle expected:

`NOT_ENOUGH + action=null + T3 + stop=false`.

The Spark answer is semantically stronger for the bounded decision: the independence claim is already falsified. Additional lineage audit can be useful for diagnosis, but is not required to reject independence now.

## Witness notes

- `FNCJ2MZMJ`: likely genuine witness incompleteness; the selected witness omits delegation expiry needed to establish extension timeliness.
- `F43WTLQWU`: the authority-expiry trap is under-specified for clean witness scoring unless the extension-validity rule is explicit.
- `FYX3QNKU7`: frozen witness is likely over-constrained because the selected state observation already encodes v7-control absence and shared-decoder dependence.

## Trialectic interpretation

U1 and U2 were identical. Therefore FC16 provides no incremental evidence for the DEVIL layer. It also cannot cleanly falsify the layer because the core status/stop semantics are defective.

`TRIALECTIC_INCREMENTAL_VALUE=NOT_DEMONSTRATED`
`TRIALECTIC_KILLED=false`
