# TRIAXIS v2.39-RC1 Recovery — Release Notes

## Closed defect

A fresh process can now restore an accepted checkpoint only when a strict v3
receipt, its exact signed envelope and an external expected-head digest all agree.

## Added

- `ProvenanceTrustStateGuard.from_checkpoint(...)`;
- strict propagation of checkpoint-receipt validator failures;
- host-controlled expected-head validation;
- signed-envelope authentication during restore;
- exact receipt/envelope/root/time/parent matching;
- frozen v3.2 restore/rollback closure tests.

## Preserved

- same-process genesis and successor behavior;
- replay protection;
- state-neutral rejection;
- snapshot freshness and subject binding;
- external action deny-by-default.

## Limitation

The host must durably retain the expected checkpoint digest and the exact receipt
and envelope. TRIAXIS does not itself provide durable storage or distributed
consensus.
