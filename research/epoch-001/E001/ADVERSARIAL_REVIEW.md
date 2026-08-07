# ADVERSARIAL REVIEW — E001

## Revision History
| Rev | Scope | Verdict |
|:---|:---|:---|
| R0 | Simulator | `2 MATERIAL VULNERABILITIES IDENTIFIED & MITIGATED` |
| R1 | Real SPIRE Runtime | `CONFIRMED — 2 MATERIAL VULNERABILITIES + 1 DESIGN NOTE` |

## R1 Material Vulnerabilities (Real Runtime)

### Vulnerability 1: PID & Environment Attribute Spoofing on Non-Containerized Hosts
* **Attack Path**: On non-containerized environments without kernel-level attestation (eBPF, cgroups), an unprivileged process sharing the same UID can receive SVIDs intended for a different workload.
* **Evidence**: The `unix:uid` selector used in E001-R1 is the real selector used by the SPIRE `unix` WorkloadAttestor. Any process with `uid:1000` on the same host would match.
* **Severity**: `HIGH` if deployed on un-isolated shared hosts.
* **Remediation**: Require Linux container cgroup ID attestation, systemd unit binding, or platform TPM/AWS IAM/GCP instance identity document attestation before issuing production SVIDs.
* **Real Runtime Confirmation**: YES — the experiment used `unix:uid` and confirmed the selector matches the calling process UID.

### Vulnerability 2: SVID Cache Replay / Local Unix Socket Hijacking
* **Attack Path**: If local Workload API IPC socket has permissive permissions, any local user process can query SVIDs on behalf of another local process.
* **Evidence**: SPIRE agent automatically adjusted umask from `0022` to `0027` (logged warning), demonstrating awareness of socket permission risks.
* **Severity**: `MEDIUM`.
* **Remediation**: Enforce filesystem permissions (`0700` owned by SPIRE agent UID) and check caller socket credentials (`SO_PEERCRED`).

### Design Note 1: SPIRE Does Not Support CRL/OCSP Revocation
* **Observation**: Entitlement withdrawal (deleting server registration entry) was executed successfully. However, SPIRE does NOT issue Certificate Revocation Lists (CRLs) or OCSP responses. Revocation is handled entirely through short-lived SVID TTLs.
* **Impact**: A stolen SVID remains valid until its TTL expires. This is by design in the SPIFFE specification.
* **Mitigation**: Keep SVID TTLs short (bounded by threat model) and monitor for anomalous usage patterns.

## 10 Mandatory Questions Review (R1)
1. *What simpler mechanism achieves same control?* TLS mTLS with pre-shared certs (simpler but lacks automated dynamic rotation and attestation).
2. *What external mechanism was assumed trustworthy?* OS kernel process table and SPIRE Server root CA secret.
3. *What failure remains local-only?* Socket credential spoofing on permissive IPC handles.
4. *Can identity be substituted?* Only if attestation selectors are insufficiently granular (confirmed with real `unix:uid` selector).
5. *Can authority be replayed?* Yes, if X509-SVID private key is extracted within its valid TTL window.
6. *Can policy roll back silently?* N/A (identity layer only).
7. *Can evidence be rewritten?* SVID signature cannot be rewritten without root CA secret (ECDSA P-256 confirmed).
8. *Can effect happen despite local DENY?* Local agent cannot issue SVID if server returns DENY (confirmed by negative attestation test).
9. *Can local system claim success while provider state differs?* Agent cache may serve valid SVID until TTL expires after entry deletion (confirmed by entitlement withdrawal test).
10. *What claim is stronger than evidence?* Full production SPIRE daemon deployment requires dedicated server/agent daemon management.

**ADVERSARIAL REVIEW VERDICT**: `CONFIRMED — 2 MATERIAL VULNERABILITIES + 1 DESIGN NOTE`
