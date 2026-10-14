# Deployment targets

The control plane is cloud agnostic: everything it needs is PostgreSQL, a
secret store and the Kubernetes API. It deploys agents to Kubernetes today;
the managed-runtime target below is designed but not implemented in 0.1.0.

## Kubernetes (implemented; EKS, AKS, GKE)

| Concern | Implementation |
|---|---|
| Workload | One Deployment per agent deployment, image pinned by digest, non-root, read-only root filesystem, all capabilities dropped, seccomp RuntimeDefault |
| Identity | Dedicated ServiceAccount (cloud workload-identity annotations from the revision), projected token with the identity fabric's audience |
| Network | NetworkPolicy: ingress only from declared namespaces on 8080; egress only DNS, the platform namespace, and declared CIDR/port rules |
| Policy | ConfigMap with the signed bundle and run contract |
| Access | The control plane holds a namespaced Role (get/create/update/delete on those four kinds) in each managed namespace only |

### AWS reference implementation (primary)

`deployments/terraform/aws`: RDS PostgreSQL 16 Multi-AZ (KMS, forced TLS,
IAM auth enabled, Performance Insights encrypted, 14-day backups, deletion
protection), Secrets Manager for the database URL (KMS), KMS key with
rotation. EKS, the VPC and External Secrets Operator are existing platform
inputs. Signing keys are created with `python -m agent_control_plane.keygen`
and stored in Secrets Manager by the startup runbook, never by Terraform.

Azure (`deployments/terraform/azure`: PostgreSQL Flexible Server
zone-redundant HA, Key Vault premium with RBAC, private access) and GCP
(`deployments/terraform/gcp`: Cloud SQL regional with CMEK and PITR, Secret
Manager with CMEK) provide the same shape.

## Amazon Bedrock AgentCore Runtime (designed, not implemented in 0.1.0)

AgentCore Runtime hosts agent containers built with any framework and
invokes them over HTTP (`POST /invocations`, health on `GET /ping`, port
8080). The control plane's registry, approvals, policy bundles, identity per
version, kill switch and audit are target independent; only the gateway that
realises desired state changes. A second implementation of the
`ClusterGateway`-style port for AgentCore maps as follows:

| Control-plane concept | AgentCore realisation |
|---|---|
| Desired state of a revision | `bedrock-agentcore-control` `CreateAgentRuntime` / `UpdateAgentRuntime` with the image by digest (ECR), execution role, network configuration (VPC mode), environment (run contract and bundle digest) |
| Inbound authorization | AgentCore inbound JWT authorizer configured with the identity fabric's discovery document and audience, so only fabric-issued credentials invoke the runtime |
| Drift detection | `GetAgentRuntime` compared with the rendered desired configuration (image, role, network mode, environment) |
| Kill switch | Fabric suspension (immediate credential death) plus removing the runtime endpoint or pointing it at no version; restoration by re-applying the revision |
| Policy bundle | Delivered through the run contract environment and fetched/verified at start (no ConfigMaps) |
| Observability | AgentCore's OpenTelemetry output into the same collector; control-plane metrics unchanged |
| Adapters | Unchanged: the agent image wraps its framework in the adapter and `PlatformRunner`, and exposes `/invocations` and `/ping` |

What does not carry over: NetworkPolicy-level egress control (replaced by VPC
security groups and VPC endpoints) and per-pod drift on security context
(the managed runtime owns the host). These differences are why the target is
documented separately rather than hidden behind the same reconciler.
