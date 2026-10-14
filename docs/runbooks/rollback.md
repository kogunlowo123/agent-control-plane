# Runbook: rollback

## Control plane

The schema is additive within a minor version (`schema_version` table), so
application rollback within 0.x.y needs no database change.

```bash
helm -n agent-platform history acp
helm -n agent-platform rollback acp <revision> --wait
kubectl -n agent-platform rollout status deployment/acp-agent-control-plane
curl -sf "$ACP/readyz"
```

Policy-only regressions: revert the commit touching
`policies/control-plane.yaml`, release, and confirm the `policy_digest`
recorded on new approvals matches the reverted file.

## An agent deployment

Roll back by applying the previous version as a new revision (the previous
version must still be approved or deprecated):

```bash
curl -X POST "$ACP/v1/deployments" -H "Authorization: Bearer $DEPLOYER_TOKEN" \
  -H 'content-type: application/json' -d @previous-revision.json
```

Production changes to HIGH/CRITICAL agents need approval as usual
(`POST /v1/deployments/<name>/approve`). The previous version's identity was
revoked when the newer rollout became available, so the rollback registers a
fresh identity for it; the newer identity is revoked once the rollback is
available.

For an immediate stop while the rollback is prepared, engage a deployment
kill switch.
