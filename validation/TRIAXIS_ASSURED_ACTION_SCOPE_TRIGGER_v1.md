# TRIAXIS Assured Action Scope Trigger v1

Checks that one valid assurance PASS attestation cannot be replayed over a
semantically different action after the attacker recomputes the outer action
scope and digest.

The trigger also requires the external issuer registry to preserve the exact
issuer-to-trust-domain mapping. A set of issuer IDs is insufficient.
