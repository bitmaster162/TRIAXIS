# TRIAXIS Competitor Map — 2026-08-05

## Category 1 — cloud agent identity and gateways

### Google Gemini Enterprise Agent Platform

Official surface: Agent Identity, Agent Registry, Agent Gateway, protocol mediation, centralized policies, MCP/A2A security, Model Armor and semantic governance policies.

- Strength over TRIAXIS: managed identity, cryptographic attestation, cloud-scale gateway and runtime enforcement.
- Adopt: agent principal, SPIFFE-class identity, gateway mediation, human delegation, centralized registry.
- TRIAXIS opportunity: connect the runtime decision to a typed claim/evidence/defeater/falsification case.

Sources:
- https://docs.cloud.google.com/iam/docs/agent-identity-overview
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/overview
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview

### Microsoft Entra Agent ID

Official surface: identity management, access protection, governance and compliance for agent identities.

- Strength: enterprise identity governance and access lifecycle.
- Adopt: agent lifecycle, ownership, access reviews and conditional access.
- TRIAXIS opportunity: evidence-backed action assurance above identity control.

Source: https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id

### Amazon Bedrock AgentCore

Official surface: AgentCore Identity, Gateway and deterministic Policy associated with gateways; policy uses Cedar.

- Strength: managed identity, credentials, gateway and fine-grained authorization.
- Adopt: inbound/outbound authorization, workload identity, policy engine association.
- TRIAXIS opportunity: decision-case and falsification provenance before policy evaluation.

Sources:
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html

## Category 2 — guardrails and runtime interception

### NVIDIA NeMo Guardrails

Official surface: policy configuration, runtime orchestration, tool-call validation and evaluation workflows.

- Strength: mature integration layer and tool interception.
- Adopt: pre-tool validation, policy configuration and evaluation workflow.
- TRIAXIS opportunity: stronger claim/evidence/state/action binding and explicit project falsification.

Sources:
- https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/overview
- https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/tool-calling

## Category 3 — agent evaluation and observability

### LangSmith

Full trajectory tracing, offline/online evaluation, human feedback, CI thresholds and monitoring.

### Galileo Agent Reliability

Agent-specific evaluation, observability and pre-tool runtime guardrails.

### Patronus AI / Percival / TRAIL

Trajectory-level issue localization, agent failure taxonomy, adaptive evaluation and simulation.

### Arize Phoenix

Open-source/local-first tracing, datasets, experiments and evaluator traces.

- Collective strength over TRIAXIS: integrations, production telemetry, datasets, UI and established evaluation workflows.
- Adopt: trace graph, trajectory metrics, evaluator calibration, production-to-regression workflow and CI release gates.
- TRIAXIS opportunity: make evidence provenance, unresolved defeaters, minimal authority and exact execution binding first-class.

Sources:
- https://www.langchain.com/langsmith/evaluation
- https://galileo.ai/agent-reliability
- https://patronus.ai/agents
- https://arize.com/phoenix

## Competitive verdict

TRIAXIS does not own identity, guardrails, observability, debate or evaluation as categories. Its defendable product hypothesis is the combined protocol:

```text
claim/evidence/defeater/falsifier
→ minimal authority request
→ exact policy/state/payload-bound authorization
→ single-use execution and durable receipt
```

This hypothesis has no moat until it is integrated into real workflows and beats simpler baselines.
