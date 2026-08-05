# TRIAXIS Operational Assurance Attestation Trigger v1

This closure trigger checks the defect discovered after v3.2-RC1:
well-formed but arbitrary Decision Assurance Case and Evidence Report digests
must not be sufficient for action authorization.

Required properties:

1. A trusted PASS attestation bound to the exact subject and digest pair keeps
   the positive path open.
2. Decision-case substitution fails closed.
3. Evidence-report substitution fails closed.
4. Issuer substitution fails closed.
5. Trust-domain substitution fails closed.
6. Absence of an external trust registry fails closed.
