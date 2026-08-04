# TRIAXIS v2.35-RC1 Recovery — Operational Delta

```text
AUTHORITY SNAPSHOT FRESHNESS

For authority-grade analysis, bind one exact host-controlled evaluation tick to
all three surfaces:

bundle.frame.evaluation_tick
trusted_evaluation_tick
authenticated_snapshot.evaluation_tick

Require exact equality. A snapshot older than the host tick is stale even when
its signature and envelope remain valid or it is re-signed later. A newer
snapshot is future state. Both must block before any checkpoint mutation.
Repeat the exact comparison at the final mutation boundary.

Do not infer live external-action permission from analytical PASS.
```
