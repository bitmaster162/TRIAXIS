# TRIAXIS v3.5 post-commit consumer expiry trigger v1

## Purpose

This trigger was authored **after** product commit
`ee1dae92cdb93c02bc5f46405bd79a85fbacea7f` and executed against a detached
checkout of the exact annotated RC1 tag.

It tests the consumer boundary rather than only the token constructor:

1. a current token remains consumable by the SQLite execution ledger;
2. policy expiry makes the ledger reject the token;
3. action-request expiry makes the ledger reject the token;
4. the effective token expiry is the exact minimum of action, policy,
   assurance, state and approval lifetimes;
5. expiry-source tampering under the original token digest is blocked.

## Expected result

`5 / 5 PASS`, including one positive control.

## Authority boundary

This evidence does not imply production readiness, independent certification,
live deployment permission, trading permission or capital permission.
