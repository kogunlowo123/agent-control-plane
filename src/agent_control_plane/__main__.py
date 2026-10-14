"""Process entry point: ``python -m agent_control_plane``."""

from __future__ import annotations

import os

import uvicorn
from agentic_core.observability import configure_logging, configure_telemetry
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from agent_control_plane import __version__
from agent_control_plane.api.app import create_app
from agent_control_plane.config import Settings
from agent_control_plane.runtime.container import build_container


def main() -> None:
    settings = Settings()  # populated from ACP_* environment variables
    configure_logging(
        service="agent-control-plane", environment=settings.environment, level=settings.log_level
    )
    exporter = None
    if settings.otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint)
    configure_telemetry(
        service_name="agent-control-plane",
        service_version=__version__,
        environment=settings.environment,
        span_exporter=exporter,
    )
    app = create_app(lambda: build_container(settings))
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
    uvicorn.run(
        app,
        host=os.environ.get("ACP_HOST", "127.0.0.1"),
        port=int(os.environ.get("ACP_PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("ACP_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
