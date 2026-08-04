# TRIAXIS v2.37-RC1 Recovery — Release Notes

## Closed defect

Malformed nested bundle values can no longer crash snapshot subject hashing.

## Added

- active authority-session contract v6;
- complete canonical JSON materialization at authority ingress;
- canonical envelope materialization before authentication;
- frozen v3.0 materialization closure;
- nested set and cyclic-input regressions.

## Preserved

Snapshot authenticity, exact time and subject binding, prepare-before-commit,
checkpoint atomicity, chain continuity and default external-action denial.
