# TRIAXIS v2.44-RC1 Recovery — Exact Product Validation

## Exact candidate

```text
commit:   fe465aabde921b6c0b94d449114cf202cc0b24da
tree:     03a396c877e03be87a56ea2442f9e9a15a37d7f7
src tree: d941c4032c8e00ca71816f0f1f56cafa043d329a
tag:      TRIAXIS-v2.44-RC1-RECOVERED
```

The candidate was checked from a clean detached Git worktree at the exact tag.

## Results

```text
Unit and historical tests: 103 / 103 PASS
Frozen checkpoint protocols v3.1-v3.8: 75 / 75 PASS
Positive controls: 32 / 32 PASS
compileall: PASS
git diff --check: PASS
worktree: CLEAN
```

This closes the v3.8 trigger for the exact product commit. It is same-lineage
validation, not independent certification or production qualification.
