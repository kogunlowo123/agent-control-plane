# Runbook: kill switch

Use the narrowest scope that contains the incident: `deployment`, then
`agent` (every deployment of one agent), then `global` (every agent; CRITICAL,
estate-wide incidents only).

## Engage

```bash
curl -X POST "$ACP/v1/kill-switches" \
  -H "Authorization: Bearer $SECOPS_TOKEN" -H 'content-type: application/json' \
  -d '{"scope":"agent","target":"claims/claims-triage","reason":"INC-1234: anomalous tool calls"}'
```

Automated responders (SOAR, threat detection) can call the MCP tool
`engage_kill_switch` or the A2A skill `engage-kill-switch` with a credential
carrying `controlplane:killswitch:engage`.

The response lists affected deployments, their phase (`Killed`) and the
identity action per deployment:

| identity action | Meaning | Do |
|---|---|---|
| `success` | Identity suspended; all credentials invalid | Nothing |
| `not_applicable` | Identity never attested (pending) | Nothing; it holds no credentials |
| `no_identity` | Fabric not configured | Nothing |
| `failed: <code>` | Fabric unreachable | Suspend manually in the fabric (`/v1/suspend`) |

A phase other than `Killed` means the cluster could not be reached at that
moment; the switch is recorded and the next reconcile enforces it. Confirm:

```bash
kubectl -n <ns> get deploy <name> -o jsonpath='{.spec.replicas}'          # 0
kubectl -n <ns> get networkpolicy <name> -o jsonpath='{.spec}'            # no ingress/egress rules
```

## Slow engagement

`ControlPlaneKillSwitchSlow` fires when engagement p99 exceeds 30 s, usually
a slow Kubernetes API or fabric. The durable record is written first, so the
switch is effective at the next reconcile even if the request timed out:
check `GET /v1/kill-switches?active=true`.

## Release

A different security officer releases (policy denies self-release):

```bash
curl -X POST "$ACP/v1/kill-switches/<id>/release" \
  -H "Authorization: Bearer $SECOPS2_TOKEN" -H 'content-type: application/json' \
  -d '{"reason":"INC-1234 resolved: prompt filter deployed in 1.0.1"}'
```

Deployments still covered by another active switch stay stopped
(`still_killed`). Released deployments get their identities reinstated and
are reconciled back to their desired replicas.
