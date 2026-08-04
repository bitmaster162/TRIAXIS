# TRIAXIS v2.35-RC1 Recovery — Operator Card

```text
1. Use host-controlled evaluation time; never accept caller-minted time.
2. Require bundle tick == host tick == authenticated snapshot tick.
3. Re-signing stale snapshot bytes does not refresh trust state.
4. A still-valid envelope does not prove current revocations or roots.
5. Reject stale/future snapshots before analytical preparation.
6. Repeat the freshness check under the checkpoint mutation lock.
7. Preserve the exact prior checkpoint on every rejection.
8. Treat the validation signer as public test infrastructure only.
9. Keep live keys, credentials and private material outside the repository.
10. External execution remains separately denied unless explicitly authorized.
```
