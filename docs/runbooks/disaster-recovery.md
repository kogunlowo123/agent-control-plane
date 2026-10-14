# Runbook: disaster recovery

| Objective | Target | Mechanism |
|---|---|---|
| RPO | ≤ 5 minutes | Managed PostgreSQL point-in-time recovery |
| RTO | ≤ 1 hour | Terraform + Helm redeploy in the recovery region |

## State that matters

- **PostgreSQL**: registry, desired state, kill switches, statuses, lease and
  audit chains. Restore with PITR.
- **Signing keys and fabric client secret**: in the secret manager
  (replicated per cloud configuration).
- **The clusters' agent workloads**: derived state; the reconciler recreates
  them from the database.

Kill switches recorded after the restore point are lost with the RPO window:
re-engage any switch from the incident record before releasing traffic.

## Procedure

1. Restore PostgreSQL to the latest point before the incident; note the
   endpoint.
2. Update the database URL secret if the endpoint changed.
3. `terraform apply` in the recovery region if the region is lost.
4. `helm upgrade --install` with the same values (managed namespaces must
   exist in the recovery cluster).
5. Re-engage kill switches from the incident record.
6. Verify `/readyz`, `GET /v1/deployments`, and that the leader's first pass
   reports deployments `Available` or `Killed`.
7. Verify audit chain continuity with `/v1/audit/verify` for each chain;
   record the cutover (new pods start new chains) in the incident ticket.

Recovery is exercised quarterly by restoring a PITR copy into a staging
namespace and running `tests/e2e` against it.
