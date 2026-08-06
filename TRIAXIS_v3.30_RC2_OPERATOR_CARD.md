# TRIAXIS v3.30-RC2 Operator Card

## Safe interpretation

`PASS` means the exact v3.30-RC1 executable reference satisfies its frozen
logical-state closure:

- a pinned threshold of distinct completion witnesses must agree on one fresh
  exact effect statement;
- any received valid blocking minority vetoes retry;
- a separate signed logical append-only completion anchor remembers provider
  outcomes while its state remains current;
- provider, completion quorum and anchor must all permit before retry;
- all evidence remains non-authorizing.

`PASS_WITH_CONDITIONS` applies because the post-RC1 probe confirmed two limits:

1. the SQLite anchor is rollbackable and is not physical WORM storage;
2. a current blocking minority protects only when its response is actually
   obtained. A rolled-back threshold can proceed if the current minority is
   omitted as unavailable and the anchor is also rolled back.

## Required execution order

1. Verify separate action authority and exact intent/target/payload/state.
2. Establish the current `IN_FLIGHT` execution-ledger head through its pinned
   quorum.
3. Query provider state.
4. Query every configured completion witness under one fresh challenge.
5. For mutating or irreversible actions, treat any missing configured witness as
   non-permissive unless an independently authorized availability policy says
   otherwise.
6. Verify the completion quorum and blocking-minority rule.
7. Query the completion anchor under a separate fresh challenge.
8. Continue only if provider, completion quorum and anchor each report `ABSENT`
   or authoritative `NO_EFFECT`.
9. Reserve completion memory before provider mutation.
10. Recheck separate action authority immediately before submission.
11. Submit stable `effect_id` as provider idempotency key.
12. Persist provider outcome, issue its signed receipt, and deliver it to all
    available witnesses and the anchor.
13. Re-anchor the final execution-ledger outcome before queue acknowledgement.

## Do

- pin both quorum configurations outside the executing agent;
- keep witness, authority, service, signer, key and trust-domain identities
  distinct;
- request all configured completion witnesses;
- fail closed on missing witnesses for high-risk effects;
- treat `RESERVED`, `UNKNOWN` and `COMPLETED` as non-retryable;
- require signed authoritative `NO_EFFECT` before another generation;
- verify anchor chain, signed head, state root and fresh status;
- preserve provider receipt, payload, request and generation binding;
- record minority disagreement, omission and unavailability as incidents.

## Do not

- call the SQLite anchor physical WORM or immutable storage;
- reset a witness or anchor to recover availability;
- let the requesting agent choose or weaken quorum membership;
- suppress a valid blocking minority;
- interpret an omitted witness as an affirmative vote;
- retry after timeout or ambiguous provider outcome;
- treat any quorum witness, receipt, head or status as action authorization;
- deploy provider, quorum thresholds, anchor, keys, backups and administrators
  in one rollback domain and call that independent;
- claim production exactly-once without provider-native immutable evidence and
  externally anchored anti-rollback state.

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
