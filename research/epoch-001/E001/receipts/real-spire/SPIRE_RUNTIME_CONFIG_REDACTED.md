# SPIRE Runtime Configuration — E001-R1 (Redacted)

## Server Configuration
* **Bind Address**: `127.0.0.1:8081`
* **Trust Domain**: `triaxis.test`
* **Socket Path**: `[WORKDIR]/spire-server.sock`
* **DataStore**: SQLite3 (disposable research)
* **NodeAttestor**: `join_token`
* **KeyManager**: `memory`
* **Default X509-SVID TTL**: `120s` (experimental)

## Agent Configuration
* **Server Address**: `127.0.0.1:8081`
* **Socket Path**: `[WORKDIR]/spire-agent.sock`
* **Trust Domain**: `triaxis.test`
* **Bootstrap**: `insecure_bootstrap = true` (research only)
* **NodeAttestor**: `join_token`
* **WorkloadAttestor**: `unix` (with `discover_workload_path = true`)

## Security Notes
* Join token: `REDACTED`
* No production credentials used
* No TLS certificates persisted beyond process lifetime
* All data in disposable `/tmp` directory
