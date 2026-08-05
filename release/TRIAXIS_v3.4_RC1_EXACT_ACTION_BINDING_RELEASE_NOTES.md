# TRIAXIS v3.4-RC1 Exact Action Binding — Release Notes

## Reason

A fresh trigger against exact v3.3-RC1 proved that a legitimate assurance
attestation could be replayed over another payload/tool/target. The failure was
committed before corrective implementation.

## Added

- exact assured-action request digest;
- Assurance PASS Attestation v2;
- Action Assurance Envelope v3;
- Authorization Token v2;
- issuer-to-trust-domain registry requirement;
- five-case assured-action closure trigger;
- updated schemas, examples and regression tests.

## Security effect

A decision/evidence PASS attestation no longer floats independently of the
actual side effect. Any change to the assured action semantics invalidates the
attestation binding.

## Boundary

This remains a local reference implementation using canonical digests and an
externally supplied trust registry. It is not production identity, signature or
complete-mediation infrastructure.
