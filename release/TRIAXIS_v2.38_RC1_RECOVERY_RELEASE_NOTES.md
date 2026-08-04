# TRIAXIS v2.38-RC1 Recovery — Release Notes

## Closed defect

Public checkpoint receipts now preserve exact parentage and detect tampering.

## Added

- checkpoint contract v3 with v2 identifier preserved;
- explicit genesis/successor parent field;
- canonical `checkpoint_sha256`;
- exported fail-closed receipt validator;
- frozen v3.1 closure regression.

## Preserved

Authority acceptance semantics, canonical ingress, snapshot authenticity,
freshness, subject binding, atomic commit and external-action denial.
