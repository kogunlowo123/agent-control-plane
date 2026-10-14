# ADR-0001: Desired-state reconciliation with spec-hash drift classification

- Status: Accepted
- Date: 2026-10-14

## Context

Agents must run exactly what was approved. Imperative "deploy" calls leave
no record of intent and cannot notice when someone edits a Deployment by
hand, adds a sidecar, or opens a NetworkPolicy. Kubernetes operators solve
this with a reconcile loop, but the control plane also needs to tell an
expected rollout (a new approved revision) apart from an unauthorised change,
because only the latter is a security signal.

## Decision

- Each deployment stores a desired revision. The reconciler renders four
  objects (ServiceAccount, ConfigMap, NetworkPolicy, Deployment) and stamps
  every object with the SHA-256 of the canonical rendering (`spec-hash`).
- Comparison is a subset diff (fields the control plane renders must match;
  server defaults are ignored), tightened by strict paths (security contexts,
  resources, NetworkPolicy rules, ConfigMap data), named-list matching that
  reports injected containers/env vars as `unexpected`, and unconditional
  findings for host namespaces and init/ephemeral containers.
- A difference on an object that carries the current spec hash is **drift**
  (counted, alerted, audited); a different or missing hash is a **rollout**.
  Both are corrected by `replace` with the read `resourceVersion`.
- `GET /v1/deployments/{name}/drift` (and the MCP/A2A equivalents) runs the
  comparison without writing.
- We use the official Kubernetes Python client with plain dict bodies and
  `_preload_content=False` reads, so comparisons use the exact wire JSON.

## Consequences

- Drift on any rendered field is corrected within one interval; additions
  outside rendered fields are only caught on strict paths (documented
  limitation; admission control remains the first line).
- `replace` (not server-side apply) means the control plane owns whole
  objects it manages; other controllers must not co-own them.
