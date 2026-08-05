# TRIAXIS v3.3-RC1 post-commit failure evidence

Exact product:

- commit `07e8b1371df806792c48b5ac6a3b89a681d92ef8`;
- tree `bbacc5531db957bda96bb217aefd3ee459cf2919`;
- 183/183 historical/unit tests PASS;
- v3.3 closure trigger 6/6 PASS.

Fresh post-product trigger result: **FAIL (1/4 PASS, 3/4 FAIL)**.

Material defects:

1. A valid PASS attestation can be replayed over a different payload after the
   action envelope and scope are recomputed.
2. The same attestation can be replayed over another policy-allowed tool and
   target.
3. A set-only trusted issuer registry validates issuer identity but erases the
   required issuer-to-trust-domain binding.

Required correction: bind a digest of the exact assured action request into the
PASS attestation and accept only an external `issuer_id -> trust_domain`
registry.
