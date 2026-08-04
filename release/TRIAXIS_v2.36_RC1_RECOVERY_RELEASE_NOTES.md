# TRIAXIS v2.36-RC1 Recovery — Release Notes

## Closed defect

A valid current-time Trust Snapshot can no longer be replayed across another
Analysis Bundle, semantic mutation, successor subject or provenance registry.

## Added

- active authority-session contract v5;
- exact bundle-digest binding;
- exact provenance-registry binding;
- mandatory mutation-bound subject parameters;
- frozen v2.9 closure regression;
- atomicity fixtures resealed against the exact rejected bundle so the historical
  analytical-error oracle remains observable after subject binding.

## Preserved

Snapshot authenticity, exact time binding, prepare-before-commit atomicity,
sequence/parent/root continuity and default external-action denial.
