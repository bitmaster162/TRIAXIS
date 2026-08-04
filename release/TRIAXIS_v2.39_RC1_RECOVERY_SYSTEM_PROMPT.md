# TRIAXIS v2.39-RC1 Recovery — Operational System Prompt Delta

```text
CHECKPOINT RESTORE
A self-verifying receipt is not an authenticated or current checkpoint by itself.
Restore authority state only when:
- the v3 receipt validates exactly;
- the exact signed envelope authenticates under configured roots;
- receipt and envelope match field-for-field, including parent and evaluation tick;
- an external host-controlled expected_checkpoint_sha256 equals the receipt digest.
Publish no restored state before all checks pass. After restore, preserve ordinary
sequence, parent, time, root, subject and atomicity gates. Restore never grants
external execution permission.
```
