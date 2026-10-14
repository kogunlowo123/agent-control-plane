"""Service metrics exposed on /metrics in Prometheus text format."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class ControlPlaneMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "acp_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        )
        self.reconcile_duration = Histogram(
            "acp_reconcile_duration_seconds",
            "Time to reconcile one deployment",
            ["outcome"],
            registry=self.registry,
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
        )
        self.reconcile_errors = Counter(
            "acp_reconcile_errors_total",
            "Deployments that failed to reconcile",
            ["error"],
            registry=self.registry,
        )
        self.drift_detected = Counter(
            "acp_drift_detected_total",
            "Out-of-band changes to managed objects, found and corrected",
            ["kind", "change"],
            registry=self.registry,
        )
        self.deployments = Gauge(
            "acp_deployments",
            "Deployments by phase after the last full reconcile",
            ["phase"],
            registry=self.registry,
        )
        self.kill_switches_active = Gauge(
            "acp_kill_switches_active",
            "Kill switches currently engaged",
            registry=self.registry,
        )
        self.kill_switch_events = Counter(
            "acp_kill_switch_events_total",
            "Kill switch engagements and releases",
            ["event", "scope"],
            registry=self.registry,
        )
        self.registry_events = Counter(
            "acp_registry_events_total",
            "Registry lifecycle events",
            ["entity", "event"],
            registry=self.registry,
        )
        self.authz_decisions = Counter(
            "acp_authorization_decisions_total",
            "Authorization decisions for agent callers (MCP, A2A, runtime)",
            ["surface", "decision"],
            registry=self.registry,
        )
        self.mcp_tool_calls = Counter(
            "acp_mcp_tool_calls_total",
            "MCP tool invocations",
            ["tool", "outcome"],
            registry=self.registry,
        )
        self.a2a_requests = Counter(
            "acp_a2a_requests_total",
            "A2A JSON-RPC requests",
            ["method", "outcome"],
            registry=self.registry,
        )
        self.leader = Gauge(
            "acp_reconciler_leader",
            "1 when this replica holds the reconciler lease",
            registry=self.registry,
        )
        self.cluster_reachable = Gauge(
            "acp_cluster_reachable",
            "1 when the Kubernetes API answered the last probe",
            registry=self.registry,
        )
