# TRIAXIS v2.36-RC1 Recovered — Post-Commit Subject Materialization Trigger

```text
EXECUTED_PRODUCT_TAG:    TRIAXIS-v2.36-RC1-RECOVERED
EXECUTED_PRODUCT_COMMIT: 10d0db544692431e2cfd152922eaac2f27c3f0f3
EXECUTED_PRODUCT_TREE:   0ffafd760e8424c2f639961208f015ee23492d3f
PROTOCOL:                TRIAXIS_AUTHORITY_SUBJECT_MATERIALIZATION_TRIGGER_v3.0_RECOVERY
RESULT:                  FAIL
CASES:                   4 / 9 PASS
FAILURES:                5 / 9
POSITIVE CONTROLS:       4 / 4 PASS
EXACT PRODUCT TESTS:     66 / 66 PASS
BYTE REPRODUCTION:       PASS across two isolated process invocations
RESULTS SHA-256:         ff821752a507e70f01f7f258c12b3cd4ddc093b24e95c7b9aaa32dc457ff1ea1
SUMMARY SHA-256:         422961462c74ba97d81c97cc98fdbefb67cad2ac78d1fabc557773f94de47fbb
```

## Triggered defect

The authority layer freezes the outer bundle with `deepcopy(dict(value))` but
computes the provenance subject digest before the low-level canonical JSON
validator. Non-canonical nested values therefore escape as Python exceptions:

```text
set             -> TypeError
NaN             -> ValueError
bytes           -> TypeError
non-string key  -> TypeError
cycle           -> RecursionError
```

All five cases must instead return a state-neutral analytical contract block.

## Oracle correction

The first exploratory run had one invalid positive control because its snapshot
belonged to a different bundle and correctly hit the v2.36 subject-binding gate.
Before evidence freeze, the fixture was corrected to bind the snapshot to the
same invalid-digest bundle. The corrected bank has 4/4 positive controls and is
the normative evidence captured here.

## Required repair

Materialize the complete Analysis Bundle into canonical detached JSON before
routing, subject hashing or analytical validation. Catch all materialization
failures and return:

```text
BLOCKED_BY_ANALYSIS_CONTRACT
invalid_analysis_bundle_materialization
```
