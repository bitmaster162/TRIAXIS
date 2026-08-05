# TRIAXIS v3.1-RC2 Research-Integrated — Validation Receipt

## Product logic

- RC1 product commit: `e2e40ae6ebab03dc2ea568845deb0a948eeb3cf2`
- RC1 product tree: `33fb77a73978369f3b182245d8d3d865e41afd7e`
- Baseline tag: `TRIAXIS-v2.44-RC2-RECOVERED`
- Baseline commit: `2408424ae0a09014e831d8ce086eb10690bd63c0`

## Exact self-run

The exact RC1 commit was checked out in a detached worktree and ran:

```text
Ran 128 tests
OK
```

The worktree remained clean. Historical v2.3-v2.44 tests and the v3.0/v3.1 assurance tests passed together.

## Research evidence

The integration was derived from three research artifacts whose SHA-256 values are recorded in `research/TRIAXIS_RESEARCH_ADJUDICATION_CASE_001.md`. The accidentally attached master dossier was used only as a restricted integration map and was not packaged.

## Closed post-commit defects

The v3.0 product failed seven fresh cases. v3.1 closes:

- evidence monoculture accepted as independent review;
- falsification without verifier-grade evidence;
- full-context adversarial review;
- stale evidence;
- malformed payload digest;
- unsafe PASS over load-bearing unknowns;
- source-correlated R3/R4 review.

## Status

- Analysis: PASS WITH CONDITIONS
- Specification: Release Candidate
- Implementation: Partially implemented
- Production-qualified: No
- Independent certification: No
- External action permission: Not implied

## Remaining boundaries

Provider/model/source metadata is still declarative unless an external identity and provenance registry attests it. Production complete mediation, KMS/SPIFFE identity, multi-host state, policy lifecycle, live-tool tests and empirical Net Governance Utility remain unimplemented or unproven.
