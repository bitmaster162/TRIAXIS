# TRIAXIS v2.44-RC1 Recovery — Pre-commit Validation

## Identity

- Trigger/evidence baseline commit: `8e6ce36b7f8bc7144316db6945d5a9e5f152fc72`
- Baseline tree: `ac9fabea2ca74fafa4039cce584ac62e12204f01`
- Staged logic/documentation tree: `cb52a9bdd946d7349a399e2432f75422d644362c`
- Run time UTC: `2026-08-04T03:55:22Z`

## Results

```text
Unit and historical tests: 103 / 103 PASS
Frozen checkpoint protocols v3.1-v3.8: 75 / 75 PASS
Positive controls: 32 / 32 PASS
compileall: PASS
git diff --check: PASS
```

The v3.8 closure includes exact namespace, checkpoint and trust-envelope scope
binding, signature verification, expiry, missing-scope rejection and positive
replication/idempotency controls.

## Evidence class

This is same-lineage pre-commit validation of a staged candidate tree. It is not
independent certification and does not establish production qualification. The
subsequent product commit must be checked again from an exact detached worktree.
