# ADR-0003: Durable kill switch enforced by desired state and credential epochs

- Status: Accepted
- Date: 2026-10-14

## Context

Stopping a misbehaving agent must be immediate, survive restarts and
redeploys, cover one deployment, one agent everywhere, or the whole estate,
and not depend on any single downstream system being healthy at that moment.
Scaling a Deployment to zero alone is undone by the next deploy or by
someone with cluster access; suspending credentials alone leaves the process
running with any data it already holds.

## Decision

- A kill switch is a durable record (scope global/agent/deployment, target,
  reason, who, when). It is written before anything else.
- Every reconcile renders the **killed variant** for any deployment an
  active switch covers: zero replicas and a deny-all NetworkPolicy. Applying
  new desired state while killed therefore never restarts the agent, and the
  periodic loop reverts manual scale-ups.
- On engagement the control plane suspends each affected identity in the
  identity fabric (credential epoch: every outstanding token fails at its
  next validation) and reconciles affected deployments immediately.
  Fabric or cluster failures are audited per deployment and never block the
  durable record.
- Engagement is never gated on approval. Release requires a different
  security officer (policy rule `deny-self-release-of-kill-switch`);
  identities are reinstated only for deployments no other active switch
  covers. Agents (SOAR, threat detection) may engage via MCP or A2A when
  their credential carries `controlplane:killswitch:engage`.
- Agent runtimes check `/v1/runtime/{deployment}` before every run and fail
  closed when the control plane is unreachable.

## Consequences

- Three independent mechanisms stop an agent: no pods, no network, no valid
  credentials.
- A global switch also stops healthy agents; it is CRITICAL-risk and used for
  estate-wide incidents only (runbook).
