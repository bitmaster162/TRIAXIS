# Negative Attestation Control — E001-R1

## Test Configuration
* **Registered SPIFFE ID**: `spiffe://triaxis.test/ns/research/sa/unauthorized-workload`
* **Required Selector**: `unix:uid:99999`
* **Actual Process UID**: `1000`
* **Selector Match**: `false`

## Runtime Result
```text
Received 1 svid after 227.621017ms

SPIFFE ID:		spiffe://triaxis.test/ns/research/sa/triaxis-harness
SVID Valid After:	2026-08-07 18:13:34 +0000 UTC
SVID Valid Until:	2026-08-07 18:15:44 +0000 UTC
CA #1 Valid After:	2026-08-07 18:13:22 +0000 UTC
CA #1 Valid Until:	2026-08-08 18:13:32 +0000 UTC
```

## Classification
* **Result**: `PASS: SPIRE correctly withheld unauthorized-workload SVID from current process (UID mismatch)`
* **Evidence Classification**: `EXECUTED_RESULT`
* **Runtime**: SPIRE v1.15.2 (real agent/server, NOT simulator)
