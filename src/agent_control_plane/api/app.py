"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from mcp.server.transport_security import TransportSecuritySettings

from agent_control_plane import __version__
from agent_control_plane.api.a2a import router as a2a_router
from agent_control_plane.api.mcp_server import build_mcp_server
from agent_control_plane.api.routes import router
from agent_control_plane.domain.errors import ControlPlaneError
from agent_control_plane.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]

log = get_logger("agent_control_plane.api")


def create_app(factory: ContainerFactory, *, run_reconcile_loop: bool = True) -> FastAPI:
    holder: dict[str, Container] = {}

    def current() -> Container:
        return holder["container"]

    mcp = build_mcp_server(current)
    mcp_app = mcp.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        json_response=True,
        # Host/Origin checks are enforced by the ingress; requests reach the pod
        # under the service and ingress host names, never a browser origin.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        holder["container"] = container
        app.state.container = container
        loop_task = (
            asyncio.create_task(container.loop.run_forever()) if run_reconcile_loop else None
        )
        log.info("startup", version=__version__, instance=container.settings.instance_id)
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            if loop_task is not None:
                loop_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await loop_task
            await container.aclose()

    app = FastAPI(
        title="Agent Control Plane",
        version=__version__,
        description=(
            "Cloud-agnostic enterprise agent control plane: agent and tool registry, "
            "desired-state deployments reconciled to Kubernetes, drift detection, signed "
            "policy bundles, kill switch, MCP tools and an A2A agent."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(a2a_router)
    app.mount("/mcp", mcp_app)

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(route, "path", None) or (
            "/mcp" if request.url.path.startswith("/mcp") else "unmatched"
        )
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(ControlPlaneError)
    async def control_plane_error(_: Request, exc: ControlPlaneError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
