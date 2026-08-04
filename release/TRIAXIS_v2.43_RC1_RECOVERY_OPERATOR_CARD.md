# TRIAXIS v2.43-RC1 Recovery — Operator Card

1. Do not trust current state unless history is exact `1..current.sequence`.
2. Missing, foreign or post-current rows are corruption, not a recoverable retry.
3. `checkpoint_store_history_incomplete` requires evidence-led recovery from a known-good copy.
4. `checkpoint_store_current_not_history_tip` means current and audit trail disagree.
5. Whole-database rollback remains outside this local-history guarantee.
