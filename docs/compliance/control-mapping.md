# Compliance control mapping

The evidence column names the artifact an auditor can inspect. The control
plane is an IT general control for AI agents; where agents process PHI or GxP
records, these controls support (not replace) the system-specific validation.

| Control objective | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | HIPAA Security Rule | 21 CFR Part 11 / GxP | Evidence |
|---|---|---|---|---|---|---|---|
| Inventory of AI agents and tools with owners | CC6.1 | 5.9, 5.12 | CM-8, PM-5 | GOVERN 1.6, MAP 1.1 | 164.308(a)(1)(ii)(A) | 11.10(d) | `/v1/agents`, `/v1/tools`, owners and escalation contacts |
| Change management with approval before production | CC8.1 | 8.32 | CM-3, CM-4, CM-5 | GOVERN 1.4, MANAGE 1.3 | 164.308(a)(8) | 11.10(k), CSA change control | Lifecycle transitions, approvals with policy digest, `deployment.approve` events |
| Separation of duties | CC5.1, CC6.3 | 5.3 | AC-5 | GOVERN 2.1 | 164.308(a)(3) | 11.10(g) | Policy rules `deny-self-*`, security tests T3/T4/T7/T14 |
| Configuration baseline and integrity | CC7.1 | 8.9 | CM-2, CM-6, SI-7 | MEASURE 2.7 | 164.312(c)(1) | 11.10(a) | Spec hash, drift reports, `deployment.drift_corrected` events |
| Least privilege for agents and the platform | CC6.3 | 5.15, 8.2 | AC-6 | MANAGE 2.4 | 164.308(a)(4) | 11.10(d) | Scopes per version, egress rules, namespaced Roles |
| Emergency stop / incident containment | CC7.4 | 5.26 | IR-4, SI-17 | MANAGE 2.3, MANAGE 4.1 | 164.308(a)(6)(ii) | — | Kill switch records and events, runbook |
| Workload and agent identity | CC6.1 | 5.16 | IA-2, IA-9 | GOVERN 1.4 | 164.312(d) | 11.300 | Fabric registrations per version, digest binding |
| Policy management and distribution | CC2.2 | 5.1 | PL-1, CM-6 | GOVERN 1.2 | 164.316(a) | 11.10(k) | Signed bundles, digests in pod templates |
| Audit trail integrity | CC7.2 | 8.15 | AU-9, AU-10 | MEASURE 2.8 | 164.312(b) | 11.10(e) | Signed hash chains, `/v1/audit/verify` |
| Secure configuration of deployed workloads | CC6.8 | 8.9, 8.19 | CM-7, SC-7 | MANAGE 2.2 | 164.312(e)(1) | — | Rendered manifests (non-root, read-only FS, NetworkPolicy) |
| Monitoring and alerting | CC7.2, CC7.3 | 8.16 | SI-4, AU-6 | MEASURE 3.1 | 164.308(a)(1)(ii)(D) | — | Prometheus alerts, dashboard |
| Availability and recovery | A1.2 | 8.13, 8.14 | CP-9, CP-10 | — | 164.308(a)(7) | — | HA database, PITR, DR runbook |

GxP / computerized system validation: the CI run for a released tag provides
OQ evidence for the functional requirements in
`docs/architecture/agent-specification.md` (each acceptance criterion maps to
named tests in `docs/architecture/overview.md`); the audit chain provides
attributable, time-stamped, tamper-evident records of who approved, deployed,
changed and stopped which agent build.
