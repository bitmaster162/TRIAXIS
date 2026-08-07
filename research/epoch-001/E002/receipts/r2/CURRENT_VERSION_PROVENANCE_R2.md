# CURRENT VERSION PROVENANCE — E002-R2

* **Work Order**: `TRIAXIS-WO-AGY-GH-002-E002-R2`
* **Execution Date**: 2026-08-08
* **Environment**: Direct Linux Python subprocess execution on WSL2 Ubuntu 24.04 (x86_64)

## Verified Primary Release Provenance (R2)

### 1. OPA (Open Policy Agent)
- **Project**: Open Policy Agent (CNCF Graduated)
- **Requested Version Line**: `v1.19.0`
- **Executed Version**: `v1.19.0` (build `1e32c796e8979b1bda2f768138500b1deb95ff24-dirty`, Go 1.26.5)
- **Release Date**: 2026-07-30
- **Download URL**: `https://github.com/open-policy-agent/opa/releases/download/v1.19.0/opa_linux_amd64_static`
- **Verified SHA-256**: `1dd5c5591ff856f5e20a1d66bafae9511ddf3c5552ed3b5070c70b2b6580ee3f`
- **License**: Apache License 2.0
- **Category Taxonomy**: `GENERAL-PURPOSE POLICY ENGINE / PDP`

### 2. OpenFGA
- **Project**: OpenFGA (CNCF Incubating)
- **Requested Version Line**: `v1.18.1`
- **Executed Server Version**: `v1.18.1` (build `69efbd95b3d44afb2e2567d485dcc792c7d79e3f`)
- **Executed CLI Version**: `fga v0.6.5` (commit `dd24e16af36637444cb77dffe3c7985a084b9838`)
- **Release Date**: 2026-06-29
- **Download URL (Server)**: `https://github.com/openfga/openfga/releases/download/v1.18.1/openfga_1.18.1_linux_amd64.tar.gz`
- **Download URL (CLI)**: `https://github.com/openfga/cli/releases/download/v0.6.5/fga_0.6.5_linux_amd64.tar.gz`
- **Verified SHA-256 (Server Binary)**: `494abb96b287606702fbf576b217632a8a95200a9894f91b9f1c2ac03de2fb06`
- **Verified SHA-256 (CLI Binary)**: `de9e6d27ef359e6448d4c699ceabec2770c65e40e2596f048e91bdf44d212df3`
- **License**: Apache License 2.0
- **Category Taxonomy**: `RELATIONSHIP-BASED AUTHORIZATION SYSTEM / ReBAC PDP`

### 3. Cedar (AWS)
- **Project**: Cedar Policy Language & Engine (AWS / Linux Foundation)
- **Executed CLI Version**: `cedar-policy-cli v4.12.0` (CLI binary `/home/bit/.cargo/bin/cedar`)
- **Executed Crate Version**: `cedar-policy v4.12.0`
- **Release Date**: 2026-07-27
- **Source Repository**: `https://github.com/cedar-policy/cedar`
- **Verified SHA-256 (CLI Binary)**: `b20d8186de45e57e13d06a981c6b562e171d7f1de94f2746c8857aa4f8126b3d`
- **License**: Apache License 2.0
- **Category Taxonomy**: `POLICY_LANGUAGE + AUTHORIZATION_ENGINE`

### 4. AuthZEN (OpenID Foundation)
- **Specification**: AuthZEN Authorization API 1.0 Final Specification
- **Official Specification URL**: `https://openid.net/specs/authorization-api-1_0.html`
- **Official Source Repository**: `https://github.com/openid/authzen`
- **License**: OpenID Foundation Intellectual Property Rights Policy / Apache-2.0
- **Category Taxonomy**: `PEP-PDP AUTHORIZATION API / INTEROPERABILITY SPECIFICATION`
