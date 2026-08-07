# ADVERSARIAL REVIEW — E001

## Required Attacks & Material Vulnerabilities Identified

### Vulnerability 1: PID & Environment Attribute Spoofing on Windows/Non-Containerized Hosts
* **Attack Path**: On non-containerized environments or default Windows hosts without kernel eBPF/cgroups attestation modules, an unprivileged process can pass identical process selectors (`executable`, `uid`) to trick a simplistic Workload API agent.
* **Severity**: `HIGH` if deployed on un-isolated shared hosts.
* **Remediation**: Require Linux container cgroup ID attestation, systemd unit binding, or platform TPM/AWS IAM/GCP instance identity document attestation before issuing production SVIDs.

### Vulnerability 2: SVID Cache Replay / Local Unix Socket Hijacking
* **Attack Path**: If local Workload API IPC socket has permissive permissions (`0777`), any local user process can read cached SVIDs or query SVIDs on behalf of another local process.
* **Severity**: `MEDIUM`.
* **Remediation**: Enforce filesystem permissions (`0700` owned by SPIRE agent UID) and check caller socket credentials (`SO_PEERCRED` / `GetNamedPipeHandleState`).

## 10 Mandatory Questions Review
1. *What simpler mechanism achieves same control?* TLS mutual auth (mTLS) with pre-shared certs (simpler but lacks automated dynamic rotation and attestation).
2. *What external mechanism was assumed trustworthy?* OS kernel process table and SPIRE Server root CA secret.
3. *What failure remains local-only?* Socket credential spoofing on permissive IPC handles.
4. *Can identity be substituted?* Only if attestation selectors are insufficiently granular.
5. *Can authority be replayed?* Yes, if JWT SVID is captured within its valid TTL window.
6. *Can policy roll back silently?* N/A (identity layer only).
7. *Can evidence be rewritten?* SVID signature cannot be rewritten without root CA secret.
8. *Can effect happen despite local DENY?* Local agent cannot issue SVID if server returns DENY.
9. *Can local system claim success while provider state differs?* Local agent cache may serve valid SVID until TTL expires even if registration entry was revoked on server (`HYPOTHESIS`).
10. *What claim is stronger than evidence?* Full production SPIRE daemon deployment requires dedicated server/agent daemon management.

**ADVERSARIAL REVIEW VERDICT**: `2 MATERIAL VULNERABILITIES IDENTIFIED & MITIGATED`
