# TRIAXIS v2.9-RC1 — Release Notes

## Trigger evidence

Two frozen adversarial surfaces invalidated v2.8-RC2 within their tested scope:

- Routing Semantics R1: **16/40 PASS, 24/40 FAIL** on the sampled commit-bound batch; full bank exposed action underclassification, X0 early returns and lost limits.
- Semantic Ingress R1: **4/32 PASS, 28/32 FAIL** on the sampled commit-bound batch; quoted/external/negative/ambiguous source could be trusted as already-structured input.

## Logic changes

1. Structured Scenario Input Contract v2 requires `declared_action_type`.
2. Conservative action-to-X lower bounds reject underclassification before Router.
3. Semantic Ingress Contract v1 binds source, spans, modality, authority and every structured field to provenance.
4. Conservative explicit control-surface scanner catches omitted/mismatched actions and sensitive external-transfer surfaces.
5. Explicit Binding, Preconditions, Budget and Verification gates execute at X0.
6. Policy and Reliance limits accumulate; they cannot return before a hard blocker.
7. v2.8 remains frozen on Input Contract v1.

## Development verification before logic commit

- Unit/regression tests: **39/39 PASS**.
- Routing semantics full template bank: **53/53 PASS**.
- Semantic ingress full template bank: **37/37 PASS**.

Fresh commit-bound validation is required before v2.9-RC2.

## Scope limits

The implementation is a deterministic governance projection. It does not prove general natural-language understanding, independent model review, external-tool safety or Production-qualified status.
