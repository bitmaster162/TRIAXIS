# TRIAXIS Research Adjudication Case 003

## Question

Can an action gate safely treat syntactically valid Decision Assurance Case and
Evidence Report digests as proof that assurance passed?

## Exact candidate

- v3.2-RC1 product commit: `1daa9b342be36c16b77e7e7b29d75ed6e8398fd7`
- product tree: `af26508be20bc9c4590e495dd5e6a9a41813678d`

## Frozen evidence

`TRIAXIS_OPERATIONAL_ASSURANCE_POSTCOMMIT_TRIGGER_v1` produced:

- positive control: 1/1 pass;
- negative substitution cases: 0/3 pass;
- overall: 1/4 pass, material failure.

The candidate allowed arbitrary decision digest substitution, arbitrary evidence
report digest substitution and an unrelated digest pair.

## Adjudication

`REVISE`.

A digest proves integrity only relative to content that somebody already trusts.
It does not prove that the content exists, passed assurance, belongs to the same
subject or was approved by a trusted authority.

## Accepted correction

Require a fresh trusted PASS attestation binding exact subject, exact decision
case and exact evidence report. Bind that attestation into action scope and the
single-use authorization token. Treat issuer identity and trust domain as
external gate inputs.

## Residual uncertainty

The local reference uses digest sealing and a configured trust registry. Real
issuer authenticity still requires KMS/PKI/SPIFFE-class identity and signature
verification at the resource boundary.
