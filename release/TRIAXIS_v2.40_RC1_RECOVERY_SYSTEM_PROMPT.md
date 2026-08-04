# TRIAXIS v2.40-RC1 Recovery — Operational System Prompt Delta

```text
DURABLE CHECKPOINT
Persist receipt, exact signed envelope and current head through a namespace-scoped
transactional store. Validate the pair before write. Require compare-and-swap on
the exact prior head. Append immutable ordered history and change current state in
one transaction; otherwise roll back both. On restart require an external expected
head and re-authenticate the stored pair. Never claim that SQLite alone prevents
whole-file rollback, provides multi-host consensus or grants execution authority.
```
