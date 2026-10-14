"""Load profile for a deployed control plane.

Run against a staging deployment, never production:

    ACP_LOAD_OPERATOR_TOKEN=<auditor IdP token> \
    ACP_LOAD_AGENT_TOKEN=<agent credential with controlplane:runtime:status> \
    ACP_LOAD_DEPLOYMENT=<a deployment name> \
    locust -f tests/performance/locustfile.py --host https://<control-plane host> \
           --users 100 --spawn-rate 10 --run-time 10m --headless

Agent runtimes poll their run status before every run, so that path
dominates; operators read inventory and drift far less often.
"""

from __future__ import annotations

import os

from locust import HttpUser, between, task

OPERATOR = os.environ.get("ACP_LOAD_OPERATOR_TOKEN", "")
AGENT = os.environ.get("ACP_LOAD_AGENT_TOKEN", "")
DEPLOYMENT = os.environ.get("ACP_LOAD_DEPLOYMENT", "")


class PlatformTraffic(HttpUser):
    wait_time = between(0.05, 0.5)

    @task(20)
    def runtime_status(self) -> None:
        self.client.get(
            f"/v1/runtime/{DEPLOYMENT}",
            headers={"Authorization": f"Bearer {AGENT}"},
            name="/v1/runtime/{name}",
        )

    @task(3)
    def list_agents(self) -> None:
        self.client.get(
            "/v1/agents?limit=50",
            headers={"Authorization": f"Bearer {OPERATOR}"},
            name="/v1/agents",
        )

    @task(2)
    def deployment_detail(self) -> None:
        self.client.get(
            f"/v1/deployments/{DEPLOYMENT}",
            headers={"Authorization": f"Bearer {OPERATOR}"},
            name="/v1/deployments/{name}",
        )

    @task(1)
    def drift(self) -> None:
        self.client.get(
            f"/v1/deployments/{DEPLOYMENT}/drift",
            headers={"Authorization": f"Bearer {OPERATOR}"},
            name="/v1/deployments/{name}/drift",
        )

    @task(1)
    def agent_card(self) -> None:
        self.client.get("/.well-known/agent-card.json", name="/.well-known/agent-card.json")
