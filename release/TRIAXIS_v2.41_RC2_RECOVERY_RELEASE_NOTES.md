# TRIAXIS v2.41-RC2 Recovery — Release Notes

## Nature of this revision

RC2 is a validation-only revision of v2.41-RC1. Product logic is byte-identical at
the Git `src` tree level:

```text
SRC TREE: 7aac55268992d113d2477f33b5bec06ac0d93211
```

## Added evidence

- 88/88 unit and historical tests;
- 48/48 cases across frozen protocols v3.1–v3.5;
- 20/20 positive controls;
- abrupt-process SQLite/WAL crash experiments before and after COMMIT;
- exact retry reconciliation after an unknown post-COMMIT outcome.

## Status

```text
SPECIFICATION: Release Candidate
IMPLEMENTATION: Partially implemented
PRODUCTION-QUALIFIED: NO
EXTERNAL EXECUTION PERMISSION: NOT IMPLIED
```
