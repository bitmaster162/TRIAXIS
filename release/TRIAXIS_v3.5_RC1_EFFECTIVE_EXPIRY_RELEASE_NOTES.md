# TRIAXIS v3.5-RC1 Effective Expiry — Release Notes

## Added

- authorization lifetime intersection across action, policy, assurance, state
  and approvals;
- auditable `expiry_sources` in authorization token v3;
- token-side minimum-expiry verification;
- execution-boundary regression trigger including approval expiry.

## Security effect

A token can no longer survive the authority or evidence freshness window that
created it.

## Boundary

External trusted time, revocation distribution, signatures and complete
mediation remain outside this local reference implementation.
