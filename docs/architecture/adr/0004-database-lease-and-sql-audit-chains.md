# ADR-0004: Stateless replicas: database leader lease and per-replica audit chains in PostgreSQL

- Status: Accepted
- Date: 2026-10-14

## Context

The reference service (agent-identity-fabric) keeps signed audit chains in
per-replica files and therefore runs as a StatefulSet. The control plane also
needs exactly one periodic reconciler at a time. Kubernetes Lease objects
would require extra RBAC in the control plane's own namespace; file-based
audit needs volumes and a log shipper.

## Decision

- **Leader lease in PostgreSQL**: table `leases`, acquired with a single
  conditional `UPDATE ... WHERE holder = me OR expires_at < now` (insert when
  absent; unique key makes concurrent inserts safe). Only the holder runs
  the periodic loop. API-triggered reconciles run on whichever replica
  serves the request; per-deployment locks and optimistic concurrency
  (`resourceVersion`) make concurrent writers safe.
- **Audit chains in PostgreSQL**: an agentic-core `AuditSink` implementation
  writes events to `audit_events (chain_id, sequence, ...)`, one hash chain
  per replica (`chain_id` = pod name), so chains never fork. Chains are
  verifiable through `/v1/audit/verify`. The service role holds INSERT and
  SELECT only on `audit_events` (runbook), making the table append-only.
- Consequently the chart uses a Deployment with an HPA, no volumes.

## Consequences

- One stateful dependency (PostgreSQL) carries everything; its HA and PITR
  are the recovery story.
- Audit evidence and operational data share a database; export to WORM
  storage is an operational job if regulation requires physical separation.
