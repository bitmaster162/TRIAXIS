# TRIAXIS v3.12-RC1 Release Notes

v3.12 closes whole-local-policy-database rollback when an independently operated Policy Head Authority remains current.

Added:

- signed challenge-bound policy-head response contract;
- exact local/remote policy head comparison;
- operator minimum version and digest pins;
- auditable idempotent response ledger;
- reference HTTP service using server-side time;
- disabled-by-default administrative install endpoint;
- systemd and Docker deployment templates;
- six-case closure trigger and schema tests.

This release remains a reference implementation. The authority itself must be placed in a separate failure and administration domain for the claimed boundary to have operational meaning.
