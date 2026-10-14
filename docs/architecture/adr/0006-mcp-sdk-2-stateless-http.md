# ADR-0006: MCP via the official SDK 2.x MCPServer, stateless streamable HTTP

- Status: Accepted
- Date: 2026-10-14

## Context

The portfolio standard calls for the official `mcp` Python SDK (FastMCP,
streamable HTTP). The current major version (2.x) renamed `FastMCP` to
`MCPServer` and otherwise keeps the decorator model, typed tool schemas and
the streamable HTTP transport. The control plane runs several replicas
behind a load balancer.

## Decision

- Use `mcp>=1.20` resolving to 2.x and `mcp.server.mcpserver.MCPServer`.
- Mount `streamable_http_app(stateless_http=True, json_response=True)` at
  `/mcp/` inside the FastAPI app; run its session manager in the app
  lifespan. Stateless mode needs no session affinity across replicas.
- DNS-rebinding protection is disabled in the SDK because the service is
  never reached by browsers and Host/Origin are enforced at the ingress;
  authorization is per tool call from the bearer credential.
- Tool errors are returned as MCP tool errors (`isError`) with the control
  plane's error code, never as protocol errors, so agents can reason about
  denials.

## Consequences

- No server-initiated requests (sampling, elicitation) are used; they would
  need stateful sessions.
- Upgrading to a future MCP major version is isolated to `api/mcp_server.py`.
