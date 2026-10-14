# Configuration reference

All settings are `ACP_*` environment variables (see
`src/agent_control_plane/config.py`). The service refuses to start with
incomplete configuration.

| Variable | Required | Default | Description |
|---|---|---|---|
| `ACP_ENVIRONMENT` | no | `production` | `production` forbids ephemeral keys |
| `ACP_PUBLIC_URL` | yes | | Public URL (agent card, injected into agent pods) |
| `ACP_INSTANCE_ID` | no | hostname | Replica id: audit chain id and lease holder (chart sets the pod name) |
| `ACP_DATABASE_URL` | yes | | SQLAlchemy async URL |
| `ACP_OPERATOR_ISSUER` | yes | | Enterprise OIDC issuer |
| `ACP_OPERATOR_AUDIENCE` | yes | | Audience of operator tokens |
| `ACP_OPERATOR_JWKS_URL` | yes | | IdP JWKS |
| `ACP_OPERATOR_ROLES_CLAIM` | no | `roles` | Claim carrying roles |
| `ACP_POLICY_FILE` | no | `policies/control-plane.yaml` | Control-plane policy set |
| `ACP_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM for audit signatures (file stem = key id) |
| `ACP_BUNDLE_KEY_FILE` | yes* | | Ed25519 PEM for policy-bundle signatures |
| `ACP_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory keys, non-production only (replaces the * settings) |
| `ACP_KUBE_MODE` | no | `in-cluster` | `in-cluster` or `kubeconfig` |
| `ACP_KUBECONFIG_PATH` | with kubeconfig | | Kubeconfig file |
| `ACP_MANAGED_NAMESPACES` | yes | | JSON list of namespaces agents may be deployed into |
| `ACP_PLATFORM_NAMESPACE` | no | `agent-platform` | Namespace agents may reach (control plane, fabric) |
| `ACP_RECONCILE_INTERVAL_S` | no | `30` | Periodic reconcile interval (1–3600) |
| `ACP_LEASE_TTL_S` | no | `45` | Leader lease TTL (5–600) |
| `ACP_FABRIC_URL` | no | | agent-identity-fabric base URL; enables identity integration and fabric authorization of agents |
| `ACP_FABRIC_TRUST_DOMAIN` | with fabric | | SPIFFE trust domain of the fabric |
| `ACP_FABRIC_WORKLOAD_AUDIENCE` | no | `identity-fabric` | Audience of projected workload tokens |
| `ACP_CLUSTER_OIDC_ISSUER` | with fabric | | Workload token issuer of the managed cluster |
| `ACP_FABRIC_ADMIN_TOKEN_URL` | with fabric | | IdP token endpoint for client credentials |
| `ACP_FABRIC_ADMIN_CLIENT_ID` | with fabric | | Client id |
| `ACP_FABRIC_ADMIN_CLIENT_SECRET` | with fabric | | Client secret (from the secret store) |
| `ACP_FABRIC_ADMIN_SCOPE` | no | `identity-fabric-admin/.default` | Scope requested |
| `ACP_LOG_LEVEL` | no | `INFO` | |
| `ACP_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint |
| `ACP_HOST` / `ACP_PORT` | no | `127.0.0.1` / `8080` | Container image sets host `0.0.0.0` |
| `ACP_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |

## Agent pod environment (set by the reconciler)

| Variable | Value |
|---|---|
| `ACP_DEPLOYMENT`, `ACP_AGENT`, `ACP_AGENT_VERSION`, `ACP_FRAMEWORK`, `ACP_ENTRYPOINT` | From the revision |
| `ACP_CONTROL_PLANE_URL`, `ACP_FABRIC_URL` | Platform URLs |
| `ACP_IDENTITY_URI` | SPIFFE ID registered for this version |
| `ACP_WORKLOAD_TOKEN_FILE` | Projected service-account token (fabric audience) |
| `ACP_POLICY_BUNDLE_FILE`, `ACP_RUN_CONTRACT_FILE` | Mounted signed bundle and run contract |
