# TRIAXIS v2.38-RC1 Recovery — Operational Delta

```text
CHECKPOINT RECEIPT

Expose a complete canonical checkpoint receipt containing the exact previous
envelope digest and a self-verifying checkpoint_sha256. Validate the digest and
all receipt fields before using serialized state. Genesis must explicitly carry
a null parent; successors must carry one exact 64-hex parent. A self-digest does
not replace a durable ledger, signature, trusted timestamp or external action
authorization.
```
