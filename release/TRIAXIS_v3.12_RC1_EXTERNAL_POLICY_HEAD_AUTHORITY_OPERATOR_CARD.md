# TRIAXIS v3.12-RC1 Operator Card

## Required before use

- Verify exact Git tag and commit.
- Provision policy-root public records out of band.
- Provision Policy Head Authority private key through a secret manager.
- Bind the service to loopback or a mutually authenticated reverse proxy.
- Keep authority policy storage separate from client policy storage.
- Configure an operator minimum policy version or exact digest for high-risk deployments.

## Fail closed on

- invalid or unknown authority signature;
- authority, trust-domain or policy-ID mismatch;
- challenge, verifier or epoch mismatch;
- expired or old response;
- local policy rollback;
- same-version fork;
- stale external authority;
- unmet operator policy floor.

## Forbidden claims

- production-qualified;
- resistant to authority-server rollback;
- independently certified;
- safe for capital, trading, wallet or destructive production actions.
