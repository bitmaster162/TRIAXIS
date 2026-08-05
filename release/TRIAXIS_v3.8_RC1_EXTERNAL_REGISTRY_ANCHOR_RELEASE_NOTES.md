# TRIAXIS v3.8-RC1 Release Notes

v3.8 closes whole-local-database rollback when a fresh independent head witness is available.

Added:

- signed external registry head witness;
- dedicated anchor key purpose;
- exact sequence/digest matching;
- rollback, fork, stale-anchor and missing-state errors;
- witness schema, tests and closure trigger.

The release does not claim replay resistance for an old but unexpired external witness.
