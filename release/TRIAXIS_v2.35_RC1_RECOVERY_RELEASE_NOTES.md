# TRIAXIS v2.35-RC1 Recovery — Release Notes

## Closed defect

Authenticated but stale trust snapshots can no longer authorize a decision at a
later host-controlled evaluation tick.

## Added

- active authority-session contract v4;
- pre-analysis snapshot freshness gate;
- commit-bound snapshot freshness recheck;
- frozen v2.8 closure regression;
- state-neutral stale genesis and stale successor tests.

## Preserved

- malformed/future envelope rejection;
- host/bundle time mismatch rejection;
- prepare-before-commit atomicity;
- exact sequence and parent checks;
- root continuity;
- all historical v2.10 and recovered v2.34 tests;
- external action denial by default.

## Scope

Same-lineage deterministic validation only. No production qualification or
independent certification.
