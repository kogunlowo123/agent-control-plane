# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Registry and approvals | Unapproved agents or tools reach production |
| Desired state and the control plane's Kubernetes access | Arbitrary workloads in managed namespaces |
| Policy bundles and the bundle signing key | Agents run under weakened policy |
| Kill switches | Misbehaving agents keep running, or healthy ones are stopped |
| Fabric administrative client | Identities registered, suspended or revoked at will |
| Audit chains | Loss of accountability |

## Trust boundaries

1. Operators, pipelines and agents → control-plane API, MCP and A2A (untrusted callers).
2. Control plane → enterprise IdP JWKS; → identity fabric.
3. Control plane → Kubernetes API (managed namespaces only).
4. Control plane → PostgreSQL and secret store.
5. Agent workloads → control plane runtime status (with fabric credentials).

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | Forged operator token claiming admin roles | Spoofing | Signature verification against IdP JWKS; asymmetric algorithms only | `tests/security::test_t1_forged_operator_token`, `test_security_primitives` |
| T2 | Valid IdP token minted for another application | Spoofing | Issuer and audience checks; time claims against the injected clock | `test_t2_token_for_another_audience` |
| T3 | Insider submits and approves own version | Elevation | Policy `deny-self-approval-of-registry-items` | `test_t3_self_approval_is_denied` |
| T4 | One approver satisfies the two-person rule twice | Elevation | Duplicate-approver check; `two-person-approval-for-high-risk` | `test_t4_single_approver_cannot_approve_high_risk_twice` |
| T5 | Tool definition changed silently after approval ("rug pull") | Tampering | Immutable tool versions pinned by schema digest; new version is a new review | `test_t5_tool_definition_cannot_change_silently` |
| T6 | Redeploy or manual scale-up bypasses a kill switch | Elevation | Killed variant rendered while any switch is active; loop reverts | `test_t6_redeploy_cannot_bypass_kill_switch` |
| T7 | Officer releases their own kill switch | Elevation | Policy `deny-self-release-of-kill-switch` | `test_t7_kill_switch_release_needs_second_person` |
| T8 | Sidecar implant, host namespace or privilege added in cluster | Tampering / Elevation | Drift rules (unexpected named items, strict security paths, host fields) and correction; alert | `test_t8_injected_sidecar_and_privilege_escalation_are_reverted` |
| T9 | NetworkPolicy opened out of band | Tampering | Strict comparison of NetworkPolicy rules; correction | `test_t9_network_policy_tampering_is_reverted` |
| T10 | Credentials embedded in desired state or reasons | Information disclosure | ContentGuard secret scan on env, annotations and free text; PII redaction | `test_t10_credentials_never_enter_desired_state` |
| T11 | Weakened policy bundle substituted | Tampering | Canonical digest + Ed25519 signature; public JWK for verification | `test_t11_policy_bundle_tampering_is_detectable`, `test_bundles` |
| T12 | Deploying into kube-system or another team's namespace | Elevation | Managed-namespace allow list; Kubernetes Role only in those namespaces | `test_t12_deployments_only_into_managed_namespaces` |
| T13 | Unauthenticated agent reads status or calls skills | Spoofing | Bearer required on runtime, MCP, A2A; fabric or local policy decides | `test_t13_agents_without_credentials_get_nothing`, `tests/e2e/test_mcp_a2a.py` |
| T14 | Requester approves own production change | Elevation | Policy `deny-self-approval-of-deployments` | `test_t14_production_change_requires_independent_approval` |
| T15 | Audit write fails silently | Repudiation | Audit failure fails the request | `tests/chaos::test_audit_failure_blocks_the_change` |
| T16 | Audit rows edited in the database | Repudiation | Hash chain + signatures; `/v1/audit/verify`; INSERT/SELECT-only grants | `test_audit_verification_detects_tampering` |
| T17 | Control plane unreachable lets agents run regardless | Elevation | `PlatformRunner` fails closed | `tests/unit/test_runner.py::test_unreachable_control_plane_fails_closed` |

## MITRE ATT&CK (Enterprise / Containers) techniques addressed

| Technique | Mitigation |
|---|---|
| T1610 Deploy Container | Only approved, digest-pinned images; managed namespaces; drift correction |
| T1611 Escape to Host | Host namespaces/privileged/init containers reported and reverted; restricted Pod Security |
| T1525 Implant Internal Image | Image digest pinning; identity bound to digest |
| T1098 Account Manipulation | Separation of duties on approvals and releases; audit |
| T1078.004 Valid Accounts: Cloud Accounts | Short-lived fabric credentials; kill switch suspends identities |
| T1562.001 Impair Defenses: Disable or Modify Tools | NetworkPolicy and security context drift reverted |
| T1528 Steal Application Access Token | No static credentials in desired state; projected time-bound tokens |

## MITRE ATLAS (AI-specific)

| Technique | Relevance | Mitigation |
|---|---|---|
| AML.T0051 LLM Prompt Injection | Injected instructions drive an agent to misuse tools | Runner input screening; scopes and kill switch bound the damage regardless of instructions |
| AML.T0053 LLM Plugin Compromise | A tool/MCP server changes behaviour | Tool versions pinned by schema digest; review required for new versions |
| AML.T0010 ML Supply Chain Compromise | Tampered agent image | Digest pinning, image digest in identity binding, SBOM and scans in CI |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Control |
|---|---|
| LLM01 Prompt Injection | Runner screens inputs; agent authority bounded by scopes, egress rules and kill switch |
| LLM02 Sensitive Information Disclosure | Output screening (credentials blocked, PII redacted); classification ceiling in identity and run contract |
| LLM03 Supply Chain | Approved tool and agent versions only; digests |
| LLM05 Improper Output Handling | Outputs never executed by the control plane; A2A free text is never interpreted as commands |
| LLM06 Excessive Agency | Scopes per version, disallowed actions in mandate, approvals, step budget, kill switch |
| LLM10 Unbounded Consumption | Step budget and timeout per run; replicas and resources pinned per revision |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Every object action is a policy decision on that resource |
| API2 Broken Authentication | Signed tokens, issuer/audience/time checks, JWKS refresh rate limiting |
| API3 Broken Object Property Level Authorization | `extra="forbid"` on every input; immutable deployment fields |
| API4 Unrestricted Resource Consumption | Paging limits, bounded list sizes, request validation, HPA |
| API5 Broken Function Level Authorization | Distinct roles per function (author, approver, deployer, policy author, security officer, auditor) |
| API6 Unrestricted Access to Sensitive Business Flows | Approval workflows; kill-switch release needs a second person |
| API8 Security Misconfiguration | Production refuses ephemeral keys; Helm `required`; restricted Pod Security; deny-by-default NetworkPolicies |
| API9 Improper Inventory Management | The registry is the inventory; unregistered agents cannot deploy |
| API10 Unsafe Consumption of APIs | Fabric and Kubernetes responses validated; failures fail closed |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Control plane's Kubernetes credentials abused | Low | High | Platform | Namespaced Roles, four kinds, no secrets/pods/RBAC; projected time-bound token; NetworkPolicy | Low |
| R2 | Bundle signing key exfiltrated | Low | High | Security Ops | Secret manager + KMS; rotation runbook; key id in every bundle | Low |
| R3 | Policy misconfiguration weakens approvals | Medium | High | AI Governance | CODEOWNERS on `policies/`; tests for every rule; policy digest on every approval | Low |
| R4 | Drift outside rendered fields undetected | Medium | Medium | Platform | Strict paths for security fields; admission policies (Kyverno/Gatekeeper) recommended | Medium |
| R5 | PostgreSQL outage | Medium | High | Platform | Multi-AZ, PITR; readiness 503; kill switches already engaged stay enforced by pods' absence | Low |
| R6 | Fabric outage during kill switch | Low | Medium | Platform | Pods and network stopped independently; suspension retried by operator; audited | Low |
