# Agent specification

The control plane is itself an agent-facing platform service (it exposes MCP
tools and an A2A agent). This document states its own mandate in the terms it
requires of every agent it manages, then defines what every registered agent
must provide.

## The control plane

### Role and mission

- **Purpose:** be the system of record and the enforcement point for which
  agents exist, which builds of them run where, under which policy, and
  whether they may run at all.
- **Business objective:** let the enterprise run agents from many frameworks
  and teams with the change control, separation of duties and emergency
  stop expected of any production system.
- **Protected resources:** registry, desired state, policy bundles and their
  signing key, kill switches, audit chains, agent workloads in managed
  namespaces.
- **Operating boundaries:** writes only ServiceAccount, ConfigMap,
  NetworkPolicy and Deployment objects, only in managed namespaces; never
  reads Secrets; never executes agent logic itself; never issues agent
  credentials (the identity fabric does).
- **Delegated responsibility:** approval rules live in
  `policies/control-plane.yaml` (owned by AI governance via CODEOWNERS);
  agent authorization on MCP/A2A is delegated to agent-identity-fabric.

### Delegated scope

| Allowed | Disallowed | Risk | Escalation |
|---|---|---|---|
| Register agents, tools, versions | Approve one's own submission | MODERATE | Denials audited; deny spike alert |
| Approve versions per policy | Approve HIGH/CRITICAL with one person | HIGH | Second approver required (`approval_recorded`) |
| Reconcile approved revisions | Deploy unapproved/retired versions, unapproved tools, unmanaged namespaces | HIGH | Production HIGH/CRITICAL changes return `approval_required` |
| Correct drift automatically | Leave drift in place | MODERATE | `OutOfBandChangesDetected`, `PrivilegedDriftDetected` alerts |
| Engage kill switches (operators, SOAR agents) | Release a kill switch one engaged oneself | CRITICAL | `KillSwitchActive` alert; second officer releases |
| Suspend/reinstate/revoke identities in the fabric | Widen any identity's scopes | HIGH | Fabric audit chain |

### Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of `/v1/*`, `/mcp/`, `/a2a` | 99.9% / 30 days |
| SLO kill switch | `POST /v1/kill-switches` to replicas 0 in the cluster | p99 < 30 s |
| SLO convergence | Time a deployment stays `Degraded` | < 10 min |
| SLO drift | Out-of-band change corrected | within one reconcile interval (30 s default) |
| SLI | `acp:request_errors:ratio_5m`, `acp_reconcile_duration_seconds`, `acp_deployments{phase}`, `acp_drift_detected_total` | Prometheus |
| KPI | Production agents with an approved version and fabric identity | 100% |
| KPI | Deployments in `Available` or `Killed` | > 99% |
| Completion | A change is complete when its outcome is in the signed audit chain and the cluster matches the rendered spec hash | Enforced: audit failure fails the request; status carries `spec_hash` |

### Permissions

| Mechanism | Use |
|---|---|
| RBAC (operators) | IdP roles `acp-agent-developer`, `acp-approver`, `acp-deployer`, `acp-policy-author`, `acp-security-officer`, `acp-auditor`, `acp-platform-admin` |
| RBAC (agents, local mode) | `acp-agent-reader`, `acp-security-automation`, `acp-agent-runtime` |
| ABAC | `policies/control-plane.yaml`: risk, environment, submitter/requester/engager vs. caller, approvals count, unrestricted egress |
| Agent identity | SPIFFE IDs from agent-identity-fabric; scopes `controlplane:*` checked by the fabric's `/v1/authorize` |
| OAuth 2.0 / OIDC | Operator bearer tokens (enterprise IdP); client-credentials for fabric administration; RFC 7523 jwt-bearer used by agent runtimes |
| Workload identity | Kubernetes RBAC Role per managed namespace; projected, time-bound API token |

### Inputs and outputs

Every request and response is a Pydantic model; JSON Schemas are in
`schemas/` and the OpenAPI document in `docs/api/openapi.json`. Inputs reject
unknown fields. Versions are semantic versions; images must be pinned by
`sha256` digest; scopes match `resource:action[:qualifier]`; egress rules are
validated CIDRs and ports; environment variable names are uppercase and may
not use the reserved `ACP_` prefix; free text and configuration are screened
by the agentic-core ContentGuard (credentials rejected, personal data
redacted).

### Provenance and audit metadata

Each approval stores the approver, time, comment and the digest of the policy
that allowed it. Each tool version stores the digest of its input schema.
Each policy bundle stores its digest, signature and key id. Each rendered
object carries the spec hash, revision generation and bundle digest. Every
decision and state change is an audit event (actor, action, resource,
outcome, correlation id, details) in a hash-chained, Ed25519-signed chain.

## What every registered agent must provide

`POST /v1/agents` and `POST /v1/agents/{ns}/{name}/versions` enforce:

| Field | Meaning |
|---|---|
| `mission` | Purpose and business objective (10–2000 chars) |
| `owners.business`, `owners.technical`, `owners.escalation_contact` | Accountability and paging |
| `risk` | LOW, MODERATE, HIGH, CRITICAL: drives approval rules |
| `max_classification` | Highest data classification the agent may touch |
| `disallowed_actions` | Explicit exclusions, carried into its identity mandate and run contract |
| `framework`, `entrypoint` | One of six supported frameworks and the object the image runs |
| `image.repository`, `image.digest` | Pinned build |
| `tools` | Registered tool versions (name, version, schema digest) |
| `scopes` | Scopes requested for its identity |
| `egress` | Allowed destinations (CIDR, ports); everything else is denied |
| `resources`, `health_path` | Requests/limits and probes |

At run time the agent image wraps its framework object in the matching
adapter and `PlatformRunner`, which checks the kill switch with the agent's
own credential before every run and enforces the run contract (timeout, step
budget, input and output screening).
