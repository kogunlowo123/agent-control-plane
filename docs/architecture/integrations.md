# Integrations: identity fabric, MCP, A2A, framework adapters

## agent-identity-fabric

| Purpose | Call | When |
|---|---|---|
| Register a workload identity | `POST /v1/agents` (admin token, client credentials) | A deployment revision with a new version becomes current |
| Suspend / reinstate | `POST /v1/suspend`, `/v1/reinstate?agent_uri=` | Kill switch engaged / released |
| Revoke | `POST /v1/revoke-agent?agent_uri=` | Superseded version once the rollout is Available; deployment deleted |
| Authorize an agent | `POST /v1/authorize` with the agent's bearer | Every MCP tool call, A2A skill and runtime status check |
| Agent credential | `POST /oauth2/token` (RFC 7523 jwt-bearer) | `PlatformRunner` in the agent image, with its projected token |
| Introspection | `POST /oauth2/introspect` | Available in the client for resource servers |

Identity naming: `spiffe://<trust-domain>/agent/<agent-namespace>/<deployment>-<version>`.
The registration binds the identity to `system:serviceaccount:<k8s-namespace>:<deployment>`,
the cluster OIDC issuer, the fabric audience, and the version's image digest,
so only that exact build running as that service account can attest. The
mandate (mission, owners, escalation contact, disallowed actions, protected
resources = its tools) is copied from the registry.

Without `ACP_FABRIC_URL`, agents are authorized by the local policy set on
their IdP roles and identities are not registered; there is no allow-all mode.

## MCP (Model Context Protocol)

Served at `/mcp/` by the official `mcp` Python SDK (`MCPServer`, the 2.x name
of FastMCP) over streamable HTTP in stateless JSON mode, mounted in the
FastAPI app. Every tool has typed input and output schemas generated from its
signature and Pydantic return model, authorizes the caller, and writes an
audit event (`mcp.<tool>`).

| Tool | Action authorized | Annotations |
|---|---|---|
| `list_agents` | `controlplane:registry:read` | read-only, idempotent |
| `get_deployment` | `controlplane:deployments:read` | read-only, idempotent |
| `detect_drift` | `controlplane:deployments:read` | read-only, idempotent |
| `runtime_status` | `controlplane:runtime:status` | read-only, idempotent |
| `engage_kill_switch` | `controlplane:killswitch:engage` | destructive |

## A2A (Agent2Agent)

- Agent Card: `GET /.well-known/agent-card.json` (protocol version, name,
  description, url, preferred transport JSON-RPC, version, capabilities,
  skills, securitySchemes bearer JWT).
- `POST /a2a`, JSON-RPC 2.0 `message/send`. The message carries a `data`
  part `{"skill": "...", "arguments": {...}}`; skills `list-agents`,
  `deployment-status`, `drift-report`, `engage-kill-switch` dispatch to the
  same operations as MCP. Results are Tasks: `completed` with a data
  artifact, `rejected` (policy deny), `input-required` (policy requires a
  human), `failed` (domain error). Missing or invalid credentials are HTTP
  401; malformed requests use JSON-RPC errors (-32700, -32600, -32601,
  -32602, -32004 unsupported operation, -32005 content type not supported).
  Free text is never interpreted as a command.

## Framework adapters

`agent_control_plane.adapters` defines the platform run contract (`RunRequest`
→ `RunResult`) and one adapter per framework. Adapters depend on the shape of
each framework's invocation API, not on the packages, so the control plane
ships without them and every agent image brings its own.

| Framework | Invocation | Mapping |
|---|---|---|
| LangGraph | `graph.ainvoke({"messages": [...], **params}, config)` | `thread_id` = session, `recursion_limit` = step budget, `__interrupt__` = human-in-the-loop |
| CrewAI | `crew.kickoff_async(inputs=...)` | `input`, `history`, parameters; `CrewOutput.raw`, `token_usage` |
| AutoGen AgentChat | `team.run(task=..., cancellation_token=...)` | token cancelled on timeout; tool calls from `ToolCallRequestEvent`; handoff = interrupt |
| Google ADK | `runner.run_async(user_id, session_id, new_message)` | session created on first use; final response event; long-running tools = interrupt; step budget on function calls |
| Microsoft Agent Framework | `agent.run(prompt, thread=...)` | thread per session (LRU); `usage_details`; user input requests = interrupt |
| AWS Strands | `agent.invoke_async(prompt)` | `AgentResult.message`, `stop_reason` mapping, `metrics.accumulated_usage`, tool metrics |

`PlatformRunner` wraps any adapter: deployment check, kill-switch check with
the agent's own credential (fail closed), input screening, timeout, step
budget, output screening. Its environment is injected by the reconciler
(`ACP_DEPLOYMENT`, `ACP_CONTROL_PLANE_URL`, `ACP_FABRIC_URL`,
`ACP_IDENTITY_URI`, `ACP_WORKLOAD_TOKEN_FILE`, `ACP_POLICY_BUNDLE_FILE`,
`ACP_RUN_CONTRACT_FILE`).

## Policy bundle distribution

Bundles (`POST /v1/policy-bundles`) are lists of agentic-core `PolicySet`
documents, validated and normalised at publication, digested over canonical
JSON and signed with the control plane's Ed25519 bundle key. The reconciler
mounts the bundle, with digest and signature, into every workload as
`/etc/acp/policy-bundle.json`; a bundle change changes the pod template
annotation and rolls the pods. Agents and gateways verify with the public JWK
at `GET /v1/policy-bundles/signing-key`.
