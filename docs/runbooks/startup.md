# Runbook: first deployment and startup

## Prerequisites

- Kubernetes ≥ 1.27 (EKS, AKS or GKE) with External Secrets Operator and a
  `ClusterSecretStore` named `platform-secrets` bound to the cloud secret
  manager.
- Target namespaces for agents created and labelled (Pod Security
  `restricted`), e.g. `agents-prod`, `agents-staging`.
- Enterprise IdP app registration for operators exposing the roles listed in
  `docs/architecture/agent-specification.md`.
- Optional: agent-identity-fabric running, and an IdP client (client
  credentials) holding the fabric's `agent-registrar` and
  `agent-security-officer` roles for the control plane.

## 1. Provision cloud resources

```bash
cd deployments/terraform/aws          # or azure / gcp
terraform init                        # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record `database_url_secret_name` and `kms_key_arn` (AWS) or the equivalents.

## 2. Restrict the audit table

Connect as the database owner once the service has created its schema
(first start), and make the audit chain append-only for the service role:

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM acp;
GRANT SELECT, INSERT ON audit_events TO acp;
```

(Run the schema creation with an owner role and the service with `acp` if
your platform separates DDL and DML roles.)

## 3. Create signing keys and the fabric client secret

```bash
uv run python -m agent_control_plane.keygen audit-2026-10 2> audit-2026-10.jwk.json \
  | aws secretsmanager create-secret --name agent-control-plane-audit-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin
uv run python -m agent_control_plane.keygen bundle-2026-10 2> bundle-2026-10.jwk.json \
  | aws secretsmanager create-secret --name agent-control-plane-bundle-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin
aws secretsmanager create-secret --name agent-control-plane-fabric-client-secret \
  --kms-key-id <kms_key_arn> --secret-string "<client secret from the IdP>"
```

Azure: `az keyvault secret set --vault-name <vault> --name ... --file /dev/stdin`.
GCP: `gcloud secrets create ... --data-file=-`.

## 4. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n agent-platform get externalsecret     # all READY=True
```

## 5. Install the chart

Create `<environment>.yaml` with every value marked REQUIRED in
`values.yaml` (public URL, managed namespaces, operator IdP, key file names
`audit-2026-10.pem` / `bundle-2026-10.pem`, and the `fabric` block if used):

```bash
helm upgrade --install acp oci://ghcr.io/kogunlowo123/charts/agent-control-plane \
  --version 0.1.0 -n agent-platform -f <environment>.yaml --wait
```

## 6. Verify

```bash
kubectl -n agent-platform rollout status deployment/acp-agent-control-plane
kubectl -n agent-platform port-forward svc/acp-agent-control-plane 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/agent-card.json | jq .name
curl -s localhost:8080/metrics | grep acp_reconciler_leader
```

Expected: `{"status":"ready"}`, the agent card, and exactly one replica
reporting `acp_reconciler_leader 1`. Then publish the first policy bundle,
register a canary agent, approve it, and deploy it to a staging namespace;
`GET /v1/deployments/<name>` should show phase `Available`.
