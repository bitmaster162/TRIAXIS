# TRIAXIS Research Adjudication Case 004

## Question

Does a PASS attestation bound to a Decision Assurance Case and Evidence Report
also authorize any policy-permitted action submitted later?

## Exact candidate

- v3.3-RC1 commit: `07e8b1371df806792c48b5ac6a3b89a681d92ef8`
- v3.3-RC1 tree: `bbacc5531db957bda96bb217aefd3ee459cf2919`

## Result

The exact candidate passed 183/183 tests and its original closure trigger 6/6.
A new post-product trigger then failed 3 of 4 cases:

- attestation replay over another payload;
- attestation replay over another allowed tool/target;
- trust-domain erasure through a set-only registry.

## Decision

`REVISE`.

The assurance artifact must cover the action semantics, not only the documents
that justified the decision. The external trust registry must preserve both
issuer identity and trust domain.

## Accepted correction

Introduce an exact `assured_action_request_sha256`, bind it into the PASS
attestation, action scope and authorization token, and reject any trust registry
that is not an issuer-to-domain mapping.
