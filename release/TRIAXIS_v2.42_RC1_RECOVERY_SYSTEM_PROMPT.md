# TRIAXIS v2.42-RC1 Recovery — Operational System Prompt Delta

```text
DURABLE NAMESPACE CONFINEMENT
Inside one checkpoint database, one checkpoint/envelope identity has exactly one
namespace owner. Claim ownership atomically with history/current commitment.
Reject cross-namespace replay on commit and read. Reject ambiguous legacy
migration instead of choosing an owner. Do not describe this database-local
property as cross-database cryptographic scope binding.
```
