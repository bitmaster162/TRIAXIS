# TRIAXIS v3.30-RC1 Operator Card

## Safe interpretation

`PASS` means the exact executable reference satisfies its frozen logical-state
closure:

- a pinned threshold of completion-witness authorities must agree on one fresh
  exact effect statement;
- any received valid blocking minority vetoes retry;
- provider outcomes are also written to a separate signed logical append-only
  completion anchor;
- provider, completion quorum and anchor must all permit before retry;
- all evidence remains non-authorizing.

`PASS` does not mean physical WORM storage, independent administration,
real-provider conformance or safety after coordinated rollback of quorum
thresholds plus the anchor.

## Required execution order

1. Verify separate action authority and exact intent/target/payload/state.
2. Establish the current `IN_FLIGHT` execution-ledger head through its pinned
   quorum.
3. Query provider state.
4. Query all available configured completion witnesses under one fresh
   challenge and verify the pinned threshold and blocking-minority rule.
5. Query the completion anchor under a separate fresh challenge.
6. Continue only if all three outcome domains report `ABSENT` or proven
   `NO_EFFECT`.
7. Reserve completion memory before provider mutation.
8. Recheck separate action authority immediately before submission.
9. Submit stable `effect_id` as provider idempotency key.
10. Persist provider outcome, issue its signed receipt, and deliver it to
    completion witnesses and the anchor.
11. Re-anchor the final execution-ledger outcome before queue acknowledgement.

## Do

- pin both quorum configurations outside the executing agent;
- keep witness, authority, service, signer, key and trust-domain identities
  distinct;
- request every configured witness when possible so a blocking minority is not
  hidden by omission;
- treat `RESERVED`, `UNKNOWN` and `COMPLETED` as non-retryable;
- require signed authoritative `NO_EFFECT` before another generation;
- verify the anchor event chain, signed head, state root and fresh status;
- preserve provider receipt, payload, request and generation binding;
- record minority disagreement and unavailability as incidents.

## Do not

- call the SQLite anchor physical WORM or immutable storage;
- reset a witness or anchor to recover availability;
- let the requesting agent choose or weaken quorum membership;
- ignore a valid blocking minority;
- infer permission from an unavailable minority;
- retry after timeout or ambiguous provider outcome;
- treat any quorum witness, receipt, head or status as action authorization;
- deploy provider, quorum thresholds, anchor, keys, backups and administrators
  in one rollback domain and call that independent;
- claim production exactly-once without provider-native immutable evidence and
  independently anchored anti-rollback state.

## Runtime flags

- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `production_qualified=false`
- `physical_independence=false`
- `administrative_independence=false`
- `physical_worm_established=false`
- `independent_certification=false`
- `real_provider_adapter=false`
