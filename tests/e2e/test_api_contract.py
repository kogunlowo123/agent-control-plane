"""Property-based API contract test: no generated input may cause a 5xx.

Requests are generated from the published OpenAPI document, both anonymous
and with a platform-admin token, so validation and authorization paths are
exercised as well as the handlers behind them.
"""

from __future__ import annotations

from typing import Any

import pytest
import schemathesis
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, assume, settings

from tests.conftest import headers
from tests.fakes import FakeIdp

pytestmark = pytest.mark.e2e


@pytest.fixture
def api_schema(client: TestClient) -> Any:
    return schemathesis.openapi.from_dict(client.get("/openapi.json").json())


schema = schemathesis.pytest.from_fixture("api_schema")


@schema.parametrize()
@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_no_server_errors(case: Any, client: TestClient, operator_idp: FakeIdp) -> None:
    # Header values must be transmittable over HTTP/1.1 at all.
    assume(all(str(v).isascii() for v in (case.headers or {}).values()))
    kwargs = case.as_transport_kwargs(base_url="")
    data = kwargs.get("data")
    raw = data if isinstance(data, bytes | str) else kwargs.get("content")
    form = data if isinstance(data, dict) else None
    for auth in ({}, headers(operator_idp, "admin@corp.test", "acp-platform-admin", "acp-auditor")):
        request_headers = {**(kwargs.get("headers") or {}), **auth}
        response = client.request(
            kwargs["method"],
            kwargs["url"],
            params=kwargs.get("params"),
            headers=request_headers,
            json=kwargs.get("json"),
            data=form,
            content=raw,
        )
        assert response.status_code < 500, (case.method, case.path, response.text)
