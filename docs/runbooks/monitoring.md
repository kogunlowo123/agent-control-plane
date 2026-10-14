# Runbook: monitoring

## Signals

| Signal | Source | Normal |
|---|---|---|
| `acp:request_errors:ratio_5m` | Recording rule | < 0.001 |
| `acp_deployments{phase}` | Leader after each pass | Available or Killed only |
| `acp_reconcile_duration_seconds` | Histogram | p99 well under the interval |
| `acp_reconcile_errors_total{error}` | Counter | Flat |
| `acp_drift_detected_total{kind,change}` | Counter | Flat; any increase is investigated |
| `acp_reconciler_leader` | Gauge per replica | Exactly one replica at 1 |
| `acp_cluster_reachable` | Gauge on the leader | 1 |
| `acp_kill_switches_active` | Gauge | 0 outside incidents |
| `acp_authorization_decisions_total{surface,decision}` | Counter | Deny share stable |
| `acp_mcp_tool_calls_total`, `acp_a2a_requests_total` | Counters | Traffic shape per release |
| Logs | JSON on stdout | `correlation_id` on every line |
| Audit | `/v1/audit/events`, `/v1/audit/verify` | Chains verify |

Alerts: `configs/prometheus/alerts.yaml`. Dashboard:
`configs/grafana/agent-control-plane.json`.

## Reconcile errors

1. `GET /v1/deployments/<name>`: `status.message` carries the cause.
2. `DependencyError`: Kubernetes API unreachable or rejecting writes. Check
   `acp_cluster_reachable`, NetworkPolicy egress to the API server, and the
   Role/RoleBinding in the target namespace (`kubectl auth can-i update
   deployments -n <ns> --as system:serviceaccount:agent-platform:agent-control-plane`).
3. `ConflictError`: another writer changed the object between read and
   replace; the next pass retries. Persistent conflicts mean another
   controller co-owns the object (see ADR-0001); remove it.
4. `NotFoundError`: the deployment references a missing version, tool or
   bundle (should be impossible through the API; check for manual database
   edits).

## No leader

Every replica reports `acp_reconciler_leader 0`: the database lease cannot be
acquired. Check database connectivity (`/readyz`) and the `leases` table:

```sql
SELECT * FROM leases;  -- holder and expires_at
```

An expired lease is taken over automatically on the next interval.

## Tracing a request

Every response carries `X-Correlation-ID`. Search logs and the audit chain:
`GET /v1/audit/events?chain=<pod>&limit=500` and filter `correlation_id`.
