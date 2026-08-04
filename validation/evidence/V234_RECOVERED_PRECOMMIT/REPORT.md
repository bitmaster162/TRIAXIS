# TRIAXIS v2.34-RC1 Recovered — Pre-Commit Validation

```text
BASELINE: 924ab55d054e58d2daf25fed6a81a8edd6226302
RESULT: PASS WITH CONDITIONS
TESTS: 56 / 56 PASS
COMPILEALL: PASS
DIFF_CHECK: PASS
```

Conditions:

1. This is a new recovery lineage, not the unavailable exact historical v2.34.
2. The v2.7 historical rows digest is preserved only after recovered oracles
   pass; `recovered_rows_sha256` records the reconstructed serializer output.
3. Snapshot freshness remains intentionally open for frozen v2.8 trigger.
4. Same-lineage validation is not independent certification.
