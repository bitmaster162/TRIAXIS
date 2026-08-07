# Entitlement Withdrawal Evidence — E001-R1

## Experiment
1. Established valid workload identity: `spiffe://triaxis.test/ns/research/sa/triaxis-harness`
2. Deleted registration entry `bd5f0502-d9cd-49fb-a402-107d4aeeebb0` from SPIRE Server
3. Waited 15s for agent entry cache sync
4. Queried Workload API again

## Results
* **Registration Entry Deleted**: `true`
* **Post-Withdrawal Workload API Response**:
```text
rpc error: code = PermissionDenied desc = no identity issued
```
* **Withdrawal Classification**: `ENTITLEMENT_WITHDRAWAL_EXECUTED — SVID no longer served after entry removal`
* **Previously-Issued SVID Status**: `SVID_REMOVED_FROM_AGENT_CACHE`
* **CRL Revocation**: `CRL_REVOCATION_NOT_EXECUTED` (SPIRE does not issue CRLs for X509-SVIDs; relies on short TTL)

## Semantic Distinction
* **Entitlement Withdrawal** (preventing new SVID issuance): `EXECUTED`
* **Certificate Revocation** (invalidating already-issued cert before TTL): `NOT_EXECUTED — SPIRE relies on short-lived SVIDs rather than CRL/OCSP`

**Evidence Classification**: `EXECUTED_RESULT`
