# TRIAXIS v2.41-RC1 Recovery — Release Notes

## Closed defect

Exact genesis and successor retries after a potentially lost acknowledgment now
return the already committed head without appending history. Reconciliation is
allowed only when immutable history proves the exact predecessor.

## Preserved

Different successors and false predecessor claims remain CAS failures; no state is
changed on rejection.
