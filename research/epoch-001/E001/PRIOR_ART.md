# PRIOR ART — SPIFFE/SPIRE WORKLOAD IDENTITY

* **Official Specification**: SPIFFE (Secure Production Identity Framework for Everyone) Standard v1.9 (`https://github.com/spiffe/spiffe`)
* **Reference Implementation**: SPIRE (SPIFFE Runtime Environment) v1.9 (`https://github.com/spiffe/spire`)
* **License**: Apache-2.0 (`SOURCE_BACKED_CLAIM`)
* **Core Mechanisms Evaluated**:
  1. **SPIFFE ID**: Uniform Resource Identifier format `spiffe://<trust-domain>/<workload-path>`.
  2. **SVID (X.509 / JWT)**: Cryptographically signed short-lived identity document.
  3. **Workload API**: Local IPC socket allowing unauthenticated local workloads to request identity via platform attestation.
  4. **Workload Attestation**: Kernel-level verification of process attributes (UID/GID, cgroups, binary SHA-256 digest, container ID).
