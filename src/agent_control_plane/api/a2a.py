"""A2A (Agent2Agent) surface: Agent Card and JSON-RPC ``message/send``.

The control plane acts as a platform-operations agent. A request message
carries a ``data`` part ``{"skill": "<id>", "arguments": {...}}``; the skill
is dispatched to the same operations the MCP tools use, so authorization
and audit are identical. Authentication happens at the HTTP layer (bearer
credential, 401 without one), as the A2A specification requires; policy
outcomes are reported as task states (``rejected``, ``input-required``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from agentic_core.domain.identifiers import new_id
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_control_plane import __version__
from agent_control_plane.application.commands import EngageKillSwitch
from agent_control_plane.application.governance import AgentCaller
from agent_control_plane.domain.errors import (
    ApprovalRequiredError,
    ControlPlaneError,
    ForbiddenError,
    UnauthorizedError,
)
from agent_control_plane.runtime.container import Container
from agent_control_plane.security.oidc import bearer_token

A2A_PROTOCOL_VERSION = "0.3.0"
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
UNSUPPORTED_OPERATION = -32004
CONTENT_TYPE_NOT_SUPPORTED = -32005

router = APIRouter()

SKILLS: list[dict[str, Any]] = [
    {
        "id": "list-agents",
        "name": "List registered agents",
        "description": "Registered agents with owners, risk tier and classification ceiling.",
        "tags": ["registry", "inventory"],
        "examples": ['{"skill": "list-agents", "arguments": {"include_retired": false}}'],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "deployment-status",
        "name": "Deployment status",
        "description": "Desired state and reconciled status of an agent deployment.",
        "tags": ["deployments", "status"],
        "examples": [
            '{"skill": "deployment-status", "arguments": {"deployment": "claims-triage"}}'
        ],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "drift-report",
        "name": "Drift report",
        "description": "Compare desired Kubernetes objects with the live cluster; read-only.",
        "tags": ["deployments", "drift"],
        "examples": ['{"skill": "drift-report", "arguments": {"deployment": "claims-triage"}}'],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "engage-kill-switch",
        "name": "Engage kill switch",
        "description": "Emergency stop of a deployment, an agent, or every agent.",
        "tags": ["safety", "kill-switch"],
        "examples": [
            '{"skill": "engage-kill-switch", "arguments": {"scope": "deployment", '
            '"target": "claims-triage", "reason": "anomalous tool calls"}}'
        ],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
]


def agent_card(c: Container) -> dict[str, Any]:
    base = c.settings.public_url_str
    return {
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "name": "Agent Control Plane",
        "description": (
            "Platform-operations agent for the enterprise agent estate: registry inventory, "
            "deployment status, drift detection and the kill switch."
        ),
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "provider": {
            "organization": "kogunlowo123",
            "url": "https://github.com/kogunlowo123/agent-control-plane",
        },
        "documentationUrl": "https://github.com/kogunlowo123/agent-control-plane",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": SKILLS,
        "securitySchemes": {
            "bearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Agent credential from agent-identity-fabric, or an IdP token",
            }
        },
        "security": [{"bearer": []}],
        "additionalInterfaces": [{"url": f"{base}/a2a", "transport": "JSONRPC"}],
    }


class DataPart(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: Literal["data"]
    data: dict[str, Any]


class TextPart(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: Literal["text"]
    text: str


class Message(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    kind: Literal["message"] = "message"
    role: Literal["user", "agent"]
    message_id: str = Field(alias="messageId", min_length=1, max_length=200)
    context_id: str | None = Field(default=None, alias="contextId", max_length=200)
    task_id: str | None = Field(default=None, alias="taskId", max_length=200)
    parts: list[Annotated[DataPart | TextPart, Field(discriminator="kind")]] = Field(min_length=1)


class SendParams(BaseModel):
    model_config = ConfigDict(extra="allow")

    message: Message
    metadata: dict[str, Any] | None = None


class SkillCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    skill: Literal["list-agents", "deployment-status", "drift-report", "engage-kill-switch"]
    arguments: dict[str, Any] = Field(default_factory=dict)


class DeploymentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deployment: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$")


class ListArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_retired: bool = False
    limit: int = Field(default=100, ge=1, le=500)


def _error(rpc_id: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": error})


def _task(
    message: Message, state: str, *, data: dict[str, Any] | None, note: str | None
) -> dict[str, Any]:
    task_id = new_id()
    context_id = message.context_id or new_id()
    status: dict[str, Any] = {"state": state, "timestamp": datetime.now(UTC).isoformat()}
    if note:
        status["message"] = {
            "kind": "message",
            "role": "agent",
            "messageId": new_id(),
            "taskId": task_id,
            "contextId": context_id,
            "parts": [{"kind": "text", "text": note}],
        }
    task: dict[str, Any] = {
        "kind": "task",
        "id": task_id,
        "contextId": context_id,
        "status": status,
        "artifacts": [],
    }
    if data is not None:
        task["artifacts"] = [
            {"artifactId": new_id(), "name": "result", "parts": [{"kind": "data", "data": data}]}
        ]
    return task


async def _dispatch(c: Container, caller: AgentCaller, call: SkillCall) -> dict[str, Any]:
    ops = c.operations
    match call.skill:
        case "list-agents":
            args = ListArgs.model_validate(call.arguments)
            listing = await ops.list_agents(
                caller, include_retired=args.include_retired, limit=args.limit
            )
            return listing.model_dump(mode="json")
        case "deployment-status":
            dep = DeploymentArgs.model_validate(call.arguments)
            return (await ops.deployment(caller, dep.deployment)).model_dump(mode="json")
        case "drift-report":
            dep = DeploymentArgs.model_validate(call.arguments)
            return (await ops.drift(caller, dep.deployment)).model_dump(mode="json")
        case "engage-kill-switch":
            command = EngageKillSwitch.model_validate(call.arguments)
            result = await ops.engage_kill_switch(caller, command)
            return result.model_dump(mode="json")


@router.get("/.well-known/agent-card.json", tags=["a2a"])
async def well_known_agent_card(request: Request) -> dict[str, Any]:
    return agent_card(request.app.state.container)


class RpcError(Exception):
    """A JSON-RPC error response for a request that cannot be processed."""

    def __init__(
        self, rpc_id: Any, code: int, message: str, *, label: str, data: Any = None
    ) -> None:
        super().__init__(message)
        self.rpc_id, self.code, self.message, self.label, self.data = (
            rpc_id,
            code,
            message,
            label,
            data,
        )


def parse_request(payload: Any) -> tuple[Any, Message, SkillCall]:
    """Validate the JSON-RPC envelope and the message/send params; raise RpcError otherwise."""
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or "method" not in payload:
        rpc = payload.get("id") if isinstance(payload, dict) else None
        raise RpcError(rpc, INVALID_REQUEST, "Invalid Request", label="invalid_request")
    rpc_id = payload.get("id")
    method = str(payload["method"])
    if method != "message/send":
        code = (
            UNSUPPORTED_OPERATION if method.startswith(("message/", "tasks/")) else METHOD_NOT_FOUND
        )
        raise RpcError(rpc_id, code, f"Method not supported: {method[:80]}", label="unsupported")
    try:
        params = SendParams.model_validate(payload.get("params"))
    except ValidationError as exc:
        raise RpcError(
            rpc_id, INVALID_PARAMS, "Invalid params", label="invalid_params", data=_errors(exc)
        ) from exc
    data_parts = [p for p in params.message.parts if isinstance(p, DataPart)]
    if not data_parts:
        raise RpcError(
            rpc_id,
            CONTENT_TYPE_NOT_SUPPORTED,
            "Send a data part {skill, arguments}; free text is not interpreted",
            label="content_type",
        )
    try:
        call = SkillCall.model_validate(data_parts[0].data)
    except ValidationError as exc:
        raise RpcError(
            rpc_id, INVALID_PARAMS, "Invalid skill call", label="invalid_params", data=_errors(exc)
        ) from exc
    return rpc_id, params.message, call


@router.post("/a2a", tags=["a2a"])
async def a2a_jsonrpc(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> JSONResponse:
    c: Container = request.app.state.container
    bearer_token(authorization)  # HTTP-layer authentication: 401 without a bearer token
    try:
        try:
            payload = await request.json()
        except ValueError as exc:
            raise RpcError(None, PARSE_ERROR, "Parse error", label="parse_error") from exc
        rpc_id, message, call = parse_request(payload)
        caller = AgentCaller(authorization, c.agent_authorizer)
        try:
            data = await _dispatch(c, caller, call)
        except ValidationError as exc:
            raise RpcError(
                rpc_id,
                INVALID_PARAMS,
                "Invalid skill arguments",
                label="invalid_params",
                data=_errors(exc),
            ) from exc
    except RpcError as err:
        c.metrics.a2a_requests.labels("message/send", err.label).inc()
        return _error(err.rpc_id, err.code, err.message, err.data)
    except UnauthorizedError:
        raise
    except ApprovalRequiredError as exc:
        task = _task(message, "input-required", data=None, note=exc.message)
        return await _respond(
            c, caller, rpc_id=rpc_id, skill=call.skill, outcome="approval_required", task=task
        )
    except ForbiddenError as exc:
        task = _task(message, "rejected", data=None, note=exc.message)
        return await _respond(
            c, caller, rpc_id=rpc_id, skill=call.skill, outcome="rejected", task=task
        )
    except ControlPlaneError as exc:
        task = _task(message, "failed", data={"error": exc.code}, note=exc.message)
        return await _respond(
            c, caller, rpc_id=rpc_id, skill=call.skill, outcome="failed", task=task
        )
    task = _task(message, "completed", data=data, note=None)
    return await _respond(
        c, caller, rpc_id=rpc_id, skill=call.skill, outcome="completed", task=task
    )


async def _respond(
    c: Container,
    caller: AgentCaller,
    *,
    rpc_id: Any,
    skill: str,
    outcome: str,
    task: dict[str, Any],
) -> JSONResponse:
    c.metrics.a2a_requests.labels("message/send", outcome).inc()
    decision = caller.last.decision.value if caller.last else "none"
    c.metrics.authz_decisions.labels("a2a", decision).inc()
    await c.recorder.record(
        caller.subject or "unauthenticated",
        "a2a.message_send",
        f"a2a:{skill}",
        outcome,
        {"task_id": task["id"]},
    )
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": task})


def _errors(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))}
        for e in exc.errors()
    ]
