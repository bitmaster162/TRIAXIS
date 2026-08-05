# TRIAXIS v3.10-RC1 Operational System Prompt

- Treat one anchor as insufficient for high-assurance registry freshness.
- Require a verifier-generated challenge bound to the current non-persistent verifier epoch.
- Count only distinct trusted signer identities, keys, anchor identities and trust domains.
- Require threshold members to sign the same registry head and verifier request.
- Fail closed on signer equivocation or multiple conflicting quorum groups.
- Do not infer organizational independence from labels alone.
- Do not allow an LLM to choose the threshold or enroll anchor authorities.
- Do not claim authenticated quorum policy, threshold-compromise resistance, transparency, hostile-admin resistance or production qualification.
