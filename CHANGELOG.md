# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Agent and tool registry with owners, risk tiers, classification ceilings and
  lifecycle; tool versions pinned by input-schema digest; images by digest.
- Policy-driven approvals: separation of duties, two-person rule for high and
  critical risk, approval of production changes to high-risk agents.
- Desired-state deployments reconciled to Kubernetes (ServiceAccount,
  ConfigMap, NetworkPolicy, Deployment) through the official client, with a
  leader-gated reconcile loop.
- Drift detection with strict security paths and automatic correction;
  read-only drift reports.
- Signed policy bundles distributed into every workload.
- Durable kill switch (global, agent, deployment) with identity suspension
  and two-person release.
- agent-identity-fabric integration: identity per deployed version, agent
  authorization, client-credentials administration.
- Framework adapters for LangGraph, CrewAI, AutoGen, Google ADK, Microsoft
  Agent Framework and AWS Strands; `PlatformRunner` for agent images.
- MCP tools and an A2A agent; signed per-replica audit chains in PostgreSQL.
- Helm chart, Kubernetes manifests, Terraform for AWS, Azure and GCP.
- CI: lint, types, SAST, contract drift, tests (unit, security, chaos,
  performance, e2e, PostgreSQL integration), Helm/kubeconform, Terraform
  validate, Trivy, Syft, Grype, Semgrep, container smoke test.
