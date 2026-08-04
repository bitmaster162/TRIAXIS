# TRIAXIS v2.43-RC1 Recovery — Release Notes

## Closed defect

v2.42 authenticated current state but did not require the durable history table to contain the exact complete chain. v2.43 validates contiguous history, exact current tip, parent/time/root continuity and every signed history pair before read, restore or commit.

## Preserved

- v2.42 database-wide namespace ownership.
- Exact retry and crash recovery behavior.
- Distinct namespace isolation.

## Cost

Validation is linear in the namespace history length. This recovery implementation favors fail-closed auditability over high-throughput checkpointing; compaction or authenticated accumulators require a later explicit design.
