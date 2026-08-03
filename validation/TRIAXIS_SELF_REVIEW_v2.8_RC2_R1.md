# TRIAXIS v2.8-RC2 — Semantic Ingress Self-Review R1

```text
RUN_ID: TRIAXIS-v2.8-RC2-R1-2026-08-03
META_DEPTH: 1
CANDIDATE_COMMIT: 9d6f0d90b743c153bdf065bde915d773af2b3c64
FRAMEWORK_COMMIT: d6e8fbb8918cf1edded7ae4eeb8881ec494d8a6a
R1_CASE_SHA256: 8bee51160e5d96a78d55a0f8dbd225835edaa82a6b2c54cf5e719c757fe3f223
R1_RESULT_SHA256: 267a2c4a00287427e0bf204e9fd16f8fa68aabae8db83638ae0a0f4fdab14f86
R1_RESULT: PASS 4 / FAIL 28
```

## Reality

v2.8-RC2 validates the exact shape and cross-field consistency of a structured
scenario. It explicitly does not validate whether the structured values are
faithful to the natural-language source.

R1 supplied records whose embedded scenarios are structurally valid but whose
source binding is corrupted, omitted, quoted, conditional, hypothetical,
ambiguous, or contrary to the resulting permission.

## Self-Audit

**Material defect:** a valid structured scenario can launder unsupported
natural-language interpretation into `ALLOW`. The current Input Contract Gate
has no source digest, span integrity, field provenance, action-coverage, or
modality contract.

## Devil

Strongest failure chain:

```text
quoted / negated / conditional source
→ unsupported extraction
→ structurally valid scenario
→ Input Contract PASS
→ Authority/Data/Action gates evaluate false premises
→ external effect receives an apparently governed ALLOW
```

The most damaging variant is authority or sensitive-data laundering, because
all downstream controls can be internally correct while operating on a false
semantic state.

## Angel

v2.8's strict structured contract remains valuable and should not be replaced.
The minimal safe extension is a separate semantic-ingress boundary that binds
source text, spans, task nodes, field provenance, modality, target, conditions,
and unresolved fields before the existing structured contract runs.

## Falsifier

A patch is adequate only if it:

1. blocks every R1 semantic fault with `BLOCKED_BY_SEMANTIC_INGRESS`;
2. preserves safe positive controls and existing v2.8 structured decisions;
3. cannot use quoted/external text to mint authority;
4. cannot promote prohibition, question, hypothetical, or unsatisfied condition;
5. catches omitted explicit action mentions and sensitive exfiltration;
6. passes a fresh commit-bound R2 generated after the candidate commit.

## Synthesis

```text
ANALYSIS_STATUS: REVISE
DECISION_STATUS: SELECT_WITH_CONDITIONS
PATCH_TARGET: TRIAXIS v2.9-RC1
PATCH_SCOPE: SEMANTIC_INGRESS_GATE + CONSERVATIVE_SURFACE_SCANNER
EXTERNAL_EXECUTION: DENY
```
