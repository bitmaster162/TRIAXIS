# TRIAXIS v3.7-RC1 Release Notes

v3.7 closes local trust-registry rollback and fork acceptance found after v3.6-RC1.

Added:

- root-signed trust registry snapshots;
- sequence and parent-digest continuity;
- durable SQLite registry head;
- rollback/fork/gap rejection;
- restart verification;
- snapshot schema, tests and closure trigger.

Whole-database rollback remains open and is not concealed by this release.
