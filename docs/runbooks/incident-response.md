# Runbook: incident response

## Misbehaving or compromised agent

1. Engage a kill switch (docs/runbooks/kill-switch.md). Pods go to zero,
   network is denied, identities are suspended.
2. Collect evidence: `GET /v1/audit/events` for `deployment.*`,
   `killswitch.*`, `mcp.*` and `a2a.*` events; the identity fabric's audit
   chain for the agent's credentials and delegations.
3. Identify the version (`GET /v1/deployments/<name>`) and deprecate it if
   the defect is in the build (`transition deprecate`); a fix ships as a new
   version through review.
4. Release the kill switch with a second officer once the fixed version is
   deployed.

## Drift

`OutOfBandChangesDetected` / `PrivilegedDriftDetected`. The control plane has
already reverted the change; the question is who made it.

1. `GET /v1/deployments/<name>`: `status.drift` lists paths, change type and
   observed values (also in the `deployment.drift_corrected` audit event).
2. Find the actor in the Kubernetes API server audit log (object, time
   window). Privileged drift (`unexpected` containers, host namespaces,
   capabilities) is treated as a security incident: consider a kill switch
   for the agent while investigating.
3. If the change was a legitimate emergency fix, make it through the control
   plane (new revision or new version) so it persists.

## Degraded deployments

`DeploymentsDegraded`: see docs/runbooks/monitoring.md#reconcile-errors.

## Cluster unreachable

`ClusterUnreachable`: the leader cannot reach the Kubernetes API. Agents keep
running as last reconciled; drift correction and new deployments pause. Kill
switches are still recorded and take effect when the API returns. Check
egress NetworkPolicy (ports 443/6443), API server health and the control
plane's projected token.

## Elevated 5xx

1. `kubectl -n agent-platform get pods`; `/readyz` per pod.
2. Readiness failing: database. Check PostgreSQL status and failover events.
3. Crash loop at start: configuration (the service refuses incomplete
   configuration; the log names the setting).
4. Audit write failures surface as 5xx by design; check database disk and
   grants on `audit_events`.
5. If a release caused it, follow docs/runbooks/rollback.md.

## Deny spike

`AgentAuthorizationDenySpike`: agents are calling without the scopes (fabric)
or roles (local) they need, typically after a policy or scope change.
Compare `policy_digest` in recent decisions with the previous release.

## Replicas down

No replica scraped: check node pressure, PDB and recent rollouts. Agents keep
running; no new changes, drift correction or kill switches until restored.
