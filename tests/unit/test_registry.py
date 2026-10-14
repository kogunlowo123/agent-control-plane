"""Registry use cases: ownership, lifecycle, separation of duties, two-person rule."""

from __future__ import annotations

import pytest
from agentic_core.domain.classification import RiskLevel

from agent_control_plane.application.commands import Reason, Transition
from agent_control_plane.domain.errors import (
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    UnsafeContentError,
)
from agent_control_plane.domain.models import (
    AgentStatus,
    EgressRule,
    Lifecycle,
    LifecycleAction,
    ToolRef,
)
from agent_control_plane.runtime.container import Container
from tests.conftest import (
    agent_command,
    deploy,
    op,
    seed,
    tool_command,
    version_command,
)

SUBMIT = Transition(action=LifecycleAction.SUBMIT)
APPROVE = Transition(action=LifecycleAction.APPROVE, comment="looks good")


async def register(c: Container, risk: RiskLevel = RiskLevel.MODERATE, **version: object) -> None:
    dev = op(c, "dev@corp.test")
    await c.registry.create_agent(agent_command(risk=risk), dev)
    await c.registry.create_version(
        "claims", "claims-triage", version_command(tools=(), **version), dev  # type: ignore[arg-type]
    )
    await c.registry.transition_version("claims", "claims-triage", "1.0.0", SUBMIT, dev)


async def test_create_and_read_agents(container: Container) -> None:
    agent = await container.registry.create_agent(agent_command(), op(container, "dev@corp.test"))
    assert agent.created_by == "dev@corp.test"
    assert (await container.registry.get_agent("claims", "claims-triage")) == agent
    listed = await container.registry.list_agents(status=AgentStatus.ACTIVE, limit=10, offset=0)
    assert [a.key for a in listed] == ["claims/claims-triage"]
    with pytest.raises(ConflictError):
        await container.registry.create_agent(agent_command(), op(container, "dev@corp.test"))
    with pytest.raises(NotFoundError):
        await container.registry.get_agent("claims", "missing")


async def test_role_is_required_to_write(container: Container) -> None:
    with pytest.raises(ForbiddenError):
        await container.registry.create_agent(agent_command(), op(container, "auditor@corp.test"))


async def test_moderate_risk_needs_one_independent_approver(container: Container) -> None:
    await register(container)
    with pytest.raises(ForbiddenError, match="denied"):  # submitter approving own work
        await container.registry.transition_version(
            "claims",
            "claims-triage",
            "1.0.0",
            APPROVE,
            op(container, "dev@corp.test", "acp-agent-developer", "acp-approver"),
        )
    result = await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver@corp.test")
    )
    assert result.outcome == "applied"
    assert result.version.state is Lifecycle.APPROVED
    assert result.version.approvals[0].policy_digest.startswith("sha256:")


async def test_high_risk_needs_two_distinct_approvers(container: Container) -> None:
    await register(container, risk=RiskLevel.HIGH)
    first = await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver@corp.test")
    )
    assert first.outcome == "approval_recorded"
    assert first.version.state is Lifecycle.IN_REVIEW
    with pytest.raises(ConflictError, match="already approved"):
        await container.registry.transition_version(
            "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver@corp.test")
        )
    second = await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver2@corp.test")
    )
    assert second.outcome == "applied"
    assert [a.actor for a in second.version.approvals] == [
        "approver@corp.test",
        "approver2@corp.test",
    ]


async def test_high_risk_with_unrestricted_egress_is_denied(container: Container) -> None:
    await register(
        container,
        risk=RiskLevel.HIGH,
        egress=(EgressRule(cidr="0.0.0.0/0", ports=(443,)),),
    )
    with pytest.raises(ForbiddenError):
        await container.registry.transition_version(
            "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver@corp.test")
        )


async def test_reject_returns_to_draft_and_clears_approvals(container: Container) -> None:
    await register(container, risk=RiskLevel.HIGH)
    await container.registry.transition_version(
        "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver@corp.test")
    )
    rejected = await container.registry.transition_version(
        "claims",
        "claims-triage",
        "1.0.0",
        Transition(action=LifecycleAction.REJECT, comment="missing threat model"),
        op(container, "approver2@corp.test"),
    )
    assert rejected.version.state is Lifecycle.DRAFT
    assert rejected.version.approvals == ()


async def test_version_requires_registered_and_approved_tools(container: Container) -> None:
    dev = op(container, "dev@corp.test")
    await container.registry.create_agent(agent_command(), dev)
    with pytest.raises(NotFoundError, match="tool"):
        await container.registry.create_version("claims", "claims-triage", version_command(), dev)
    await container.registry.create_tool(tool_command(), dev)
    await container.registry.create_version("claims", "claims-triage", version_command(), dev)
    await container.registry.transition_version("claims", "claims-triage", "1.0.0", SUBMIT, dev)
    with pytest.raises(InvalidStateError, match="approve it first"):
        await container.registry.transition_version(
            "claims", "claims-triage", "1.0.0", APPROVE, op(container, "approver@corp.test")
        )


async def test_tool_lifecycle_pins_schema(container: Container) -> None:
    dev = op(container, "dev@corp.test")
    tool = await container.registry.create_tool(tool_command(), dev)
    assert tool.schema_digest.startswith("sha256:")
    await container.registry.transition_tool("claims.search", "1.0.0", SUBMIT, dev)
    approved = await container.registry.transition_tool(
        "claims.search", "1.0.0", APPROVE, op(container, "approver@corp.test")
    )
    assert approved.tool.state is Lifecycle.APPROVED
    assert approved.tool.schema_digest == tool.schema_digest
    deprecated = await container.registry.transition_tool(
        "claims.search",
        "1.0.0",
        Transition(action=LifecycleAction.DEPRECATE),
        op(container, "admin@corp.test"),
    )
    assert deprecated.tool.state is Lifecycle.DEPRECATED
    assert [t.key for t in await container.registry.list_tools(state=None, limit=5, offset=0)] == [
        "claims.search@1.0.0"
    ]
    with pytest.raises(NotFoundError):
        await container.registry.get_tool("claims.search", "9.9.9")


async def test_high_risk_tool_needs_two_approvers(container: Container) -> None:
    dev = op(container, "dev@corp.test")
    risky = tool_command("payments.execute").model_copy(update={"risk": RiskLevel.CRITICAL})
    await container.registry.create_tool(risky, dev)
    await container.registry.transition_tool("payments.execute", "1.0.0", SUBMIT, dev)
    first = await container.registry.transition_tool(
        "payments.execute", "1.0.0", APPROVE, op(container, "approver@corp.test")
    )
    assert first.outcome == "approval_recorded"
    with pytest.raises(ConflictError):
        await container.registry.transition_tool(
            "payments.execute", "1.0.0", APPROVE, op(container, "approver@corp.test")
        )
    second = await container.registry.transition_tool(
        "payments.execute", "1.0.0", APPROVE, op(container, "approver2@corp.test")
    )
    assert second.tool.state is Lifecycle.APPROVED


async def test_tool_schema_must_be_an_object(container: Container) -> None:
    bad = tool_command().model_copy(update={"input_schema": {"type": "string"}})
    with pytest.raises(InvalidStateError):
        await container.registry.create_tool(bad, op(container, "dev@corp.test"))


async def test_cannot_retire_deployed_version_but_can_deprecate(container: Container) -> None:
    await seed(container)
    await deploy(container)
    with pytest.raises(InvalidStateError, match="deprecate instead"):
        await container.registry.transition_version(
            "claims",
            "claims-triage",
            "1.0.0",
            Transition(action=LifecycleAction.RETIRE),
            op(container, "admin@corp.test"),
        )
    deprecated = await container.registry.transition_version(
        "claims",
        "claims-triage",
        "1.0.0",
        Transition(action=LifecycleAction.DEPRECATE),
        op(container, "admin@corp.test"),
    )
    assert deprecated.version.state is Lifecycle.DEPRECATED
    # A deprecated version keeps running where it is deployed and can still be scaled.
    scaled = await deploy(container, replicas=3)
    assert scaled.outcome == "applied"


async def test_retire_agent_requires_no_deployments(container: Container) -> None:
    await seed(container)
    await deploy(container)
    reason = Reason(reason="replaced by claims-intake")
    with pytest.raises(InvalidStateError, match="still has deployments"):
        await container.registry.retire_agent(
            "claims", "claims-triage", reason, op(container, "admin@corp.test")
        )
    await container.deployments.delete(
        "claims-triage-prod", reason, op(container, "deployer@corp.test")
    )
    retired = await container.registry.retire_agent(
        "claims", "claims-triage", reason, op(container, "admin@corp.test")
    )
    assert retired.agent.status is AgentStatus.RETIRED
    assert retired.retired_versions == ("1.0.0",)
    with pytest.raises(InvalidStateError):
        await container.registry.retire_agent(
            "claims", "claims-triage", reason, op(container, "admin@corp.test")
        )
    with pytest.raises(InvalidStateError, match="retired"):
        await container.registry.create_version(
            "claims",
            "claims-triage",
            version_command("2.0.0", tools=()),
            op(container, "dev@corp.test"),
        )
    versions = await container.registry.list_versions("claims", "claims-triage")
    assert {v.state for v in versions} == {Lifecycle.RETIRED}


async def test_free_text_is_screened(container: Container) -> None:
    leaky = agent_command().model_copy(
        update={"mission": "Uses key AKIAIOSFODNN7EXAMPLE to read claims from storage."}
    )
    with pytest.raises(UnsafeContentError):
        await container.registry.create_agent(leaky, op(container, "dev@corp.test"))
    personal = agent_command().model_copy(
        update={"mission": "Escalates claims to jane.doe@example.org when the adjuster is away."}
    )
    agent = await container.registry.create_agent(personal, op(container, "dev@corp.test"))
    assert "jane.doe@example.org" not in agent.mission


async def test_unknown_tool_reference_in_version(container: Container) -> None:
    dev = op(container, "dev@corp.test")
    await container.registry.create_agent(agent_command(), dev)
    with pytest.raises(NotFoundError):
        await container.registry.create_version(
            "claims",
            "claims-triage",
            version_command(tools=(ToolRef(name="does.not.exist", version="1.0.0"),)),
            dev,
        )
    with pytest.raises(NotFoundError):
        await container.registry.get_version("claims", "claims-triage", "1.0.0")
