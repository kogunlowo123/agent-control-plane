# Agent Control Plane

A cloud-agnostic control plane for enterprise AI agents. It is the system of
record for which agents and tools exist, who owns them and how risky they
are; it turns approved versions into desired state that it reconciles to
Kubernetes, reports and reverts drift, distributes signed policy bundles,
registers a workload identity for every deployed version with
[agent-identity-fabric](https://github.com/kogunlowo123/agent-identity-fabric),
and stops any agent, or all of them, with a durable kill switch. Agents
built with LangGraph, CrewAI, AutoGen, Google ADK, Microsoft Agent Framework
and AWS Strands run behind one platform run contract.

```
Registry ─▶ Identity ─▶ Policy ─▶ Runtime ─▶ Observability
```

## Capabilities

| Capability | Implementation |
|---|---|
| Agent and tool registry | Versions (semver), owners, escalation contact, risk tier, classification ceiling, lifecycle draft → in_review → approved → deprecated → retired; tools pinned by input-schema digest; images pinned by sha256 |
| Approvals | Policy-driven (agentic-core PolicyEngine): no self-approval, two distinct approvers for HIGH/CRITICAL, production changes to HIGH/CRITICAL agents need an approver other than the requester |
| Desired state | Deployment revisions (version, replicas, bundle, ingress namespaces, config) reconciled to ServiceAccount, ConfigMap, NetworkPolicy and Deployment via the official Kubernetes client |
| Drift detection | Subset diff tolerant of server defaults, strict on security contexts, resources, network rules and config; injected containers, host namespaces and privileges always flagged; read-only `/drift`; automatic correction |
| Identity | One fabric identity per deployed version, bound to the service account and image digest; superseded identities revoked once the rollout is available |
| Policy bundles | Validated agentic-core policy sets, canonical digest, Ed25519 signature, mounted into every workload |
| Kill switch | Global, per agent, per deployment; zero replicas + deny-all network + suspended credentials; survives redeploys; release by a second officer |
| Framework adapters | LangGraph, CrewAI, AutoGen, Google ADK, Microsoft Agent Framework, AWS Strands; `PlatformRunner` enforces kill switch (fail closed), timeout, step budget, content screening |
| MCP | `list_agents`, `get_deployment`, `detect_drift`, `runtime_status`, `engage_kill_switch` over streamable HTTP at `/mcp/` |
| A2A | Agent Card at `/.well-known/agent-card.json`; JSON-RPC `message/send` at `/a2a` |
| Audit | agentic-core hash-chained, Ed25519-signed events in PostgreSQL, one chain per replica, verifiable via API |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation IDs, alert rules, Grafana dashboard |

Shared controls (policy engine, audit chain, content guard, logging,
telemetry) come from [agentic-core](https://github.com/kogunlowo123/agentic-core).

## Quick start (local)

Requires Docker and [kind](https://kind.sigs.k8s.io/). No API keys or cloud
credentials are needed.

```bash
kind create cluster --name acp
kind get kubeconfig --name acp --internal > .kind-kubeconfig
kubectl create namespace agents-dev
KIND_KUBECONFIG=$PWD/.kind-kubeconfig docker compose up --build
curl -s localhost:8080/.well-known/agent-card.json | jq .skills
```

The compose stack runs PostgreSQL, an OIDC provider for operator tokens and
an OpenTelemetry collector; the control plane reconciles into the kind
cluster.

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
make integration  # PostgreSQL integration tests (needs ACP_TEST_DATABASE_URL)
make helm terraform
```

Test suites: `tests/unit`, `tests/security` (attacks mapped to the threat
model), `tests/chaos` (Kubernetes, fabric, database and audit failures),
`tests/performance` (latency budgets; `locustfile.py` for load), `tests/e2e`
(HTTP lifecycle, MCP and A2A in both authorization modes, property-based
OpenAPI contract test), `tests/integration` (PostgreSQL). Kubernetes is
exercised through the real client against an in-memory API server; the
identity fabric through its HTTP contract on `httpx.MockTransport`.

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST/GET /v1/agents`, `GET /v1/agents/{ns}/{name}`, `POST .../retire` | Developers, auditors, admins | Agent registry |
| `POST/GET /v1/agents/{ns}/{name}/versions`, `POST .../versions/{v}/transitions` | Developers, approvers | Versions and lifecycle |
| `POST/GET /v1/tools`, `POST /v1/tools/{name}/{v}/transitions` | Developers, approvers | Tool registry |
| `POST/GET /v1/policy-bundles`, `GET /v1/policy-bundles/signing-key` | Policy authors, agents | Signed policy bundles |
| `POST /v1/deployments`, `POST .../{name}/approve`, `.../delete`, `.../reconcile` | Deployers, approvers | Desired state |
| `GET /v1/deployments/{name}`, `.../drift`, `.../manifests` | Operators, auditors | Status, drift, rendered objects |
| `POST/GET /v1/kill-switches`, `POST .../{id}/release` | Security officers | Kill switch |
| `GET /v1/runtime/{name}` | Agent runtimes (fabric credential) | May this deployment run now? |
| `GET /v1/audit/chains`, `/events`, `/verify` | Auditors | Audit evidence |
| `/mcp/`, `/a2a`, `/.well-known/agent-card.json` | Agents | MCP tools, A2A agent |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/agent-control-plane` (Deployment, HPA, PDB, NetworkPolicy, namespaced Roles in managed namespaces, ServiceMonitor) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, default deny, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}`: managed PostgreSQL, KMS, secret store. AWS is the reference; Amazon Bedrock AgentCore is documented as a target in [deployment targets](docs/architecture/deployment-targets.md) |

See the [startup runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md), [agent specification](docs/architecture/agent-specification.md), [integrations](docs/architecture/integrations.md), [deployment targets](docs/architecture/deployment-targets.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [kill switch](docs/runbooks/kill-switch.md), [incident response](docs/runbooks/incident-response.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md)

## License

Apache-2.0
