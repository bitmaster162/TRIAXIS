# TRIAXIS Research Adjudication Case 005

## Exact candidate

v3.4-RC1 commit `1ec7eafbdfff5a25bd7256c49d90917be673a922`.

## New post-product result

The candidate passed 187/187 tests, artifact-binding trigger 6/6 and exact-action
scope trigger 5/5. A new temporal trigger then failed 3/4 cases: authorization
survived policy, assurance and state expiry.

## Decision

`REVISE`.

Authorization is a derived capability and its lifetime is the intersection of
all source lifetimes, not an independently chosen action-envelope TTL.

## Accepted correction

Use the earliest action, policy, assurance, state or approval expiry; record the
source projection in the token and revalidate it at the execution boundary.
