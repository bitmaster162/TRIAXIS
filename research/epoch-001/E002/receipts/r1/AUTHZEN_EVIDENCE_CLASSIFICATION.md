# AUTHZEN EVIDENCE CLASSIFICATION — E002-R1

* **Classification**: `AUTHZEN_INTERFACE_CONFORMANCE_MODEL` / `LOCAL_ADAPTER_MODEL_ONLY`
* **Reason**: AuthZEN 1.0 is an OpenID Foundation PEP-PDP REST API specification profile, NOT a standalone policy evaluation engine.

## Interface Conformance Testing
The AuthZEN adapter in TRIAXIS maps the standard AuthZEN 1.0 REST API payload:

### AuthZEN Request Payload (`/evaluation`)
```json
{
  "subject": {
    "type": "User",
    "id": "alice",
    "properties": {
      "human_id": "human_alice",
      "agent_instance_id": "agent_inst_1"
    }
  },
  "action": {
    "name": "read"
  },
  "resource": {
    "type": "Document",
    "id": "doc_1"
  },
  "context": {
    "network": "internal",
    "policy_version": "v1"
  }
}
```

### AuthZEN Response Payload
```json
{
  "decision": true,
  "context": {
    "reasons": ["Matching permit policy in Cedar PDP"]
  }
}
```

## Transport & Failure Mode Verification
* **PDP Unreachable**: PEP adapter returns `decision: false` (Fail-Closed)
* **Malformed Request**: PEP adapter returns `decision: false` (Fail-Closed)
* **Underlying Policy Semantics**: Credited to Cedar / OpenFGA PDPs behind the AuthZEN boundary, NOT to AuthZEN itself.
