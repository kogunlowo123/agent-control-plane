"""Domain model invariants: lifecycle, validation, kill-switch coverage."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_control_plane.domain.errors import InvalidStateError
from agent_control_plane.domain.models import (
    Approval,
    DeploymentSpec,
    DeploymentState,
    EgressRule,
    Environment,
    KillScope,
    KillSwitch,
    Lifecycle,
    LifecycleAction,
    ToolVersion,
    next_state,
)
from tests.conftest import agent_command, tool_command, version_command

NOW = datetime(2026, 10, 14, tzinfo=UTC)


def spec(
    name: str = "claims-triage-prod", agent: tuple[str, str] = ("claims", "claims-triage")
) -> DeploymentSpec:
    return DeploymentSpec(
        name=name,
        agent_namespace=agent[0],
        agent_name=agent[1],
        environment=Environment.PRODUCTION,
        namespace="agents-prod",
        state=DeploymentState.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )


@pytest.mark.parametrize(
    ("state", "action", "target"),
    [
        (Lifecycle.DRAFT, LifecycleAction.SUBMIT, Lifecycle.IN_REVIEW),
        (Lifecycle.IN_REVIEW, LifecycleAction.APPROVE, Lifecycle.APPROVED),
        (Lifecycle.IN_REVIEW, LifecycleAction.REJECT, Lifecycle.DRAFT),
        (Lifecycle.APPROVED, LifecycleAction.DEPRECATE, Lifecycle.DEPRECATED),
        (Lifecycle.DEPRECATED, LifecycleAction.RETIRE, Lifecycle.RETIRED),
        (Lifecycle.DRAFT, LifecycleAction.RETIRE, Lifecycle.RETIRED),
    ],
)
def test_lifecycle_transitions(
    state: Lifecycle, action: LifecycleAction, target: Lifecycle
) -> None:
    assert next_state(state, action) is target


@pytest.mark.parametrize(
    ("state", "action"),
    [
        (Lifecycle.DRAFT, LifecycleAction.APPROVE),
        (Lifecycle.APPROVED, LifecycleAction.SUBMIT),
        (Lifecycle.RETIRED, LifecycleAction.DEPRECATE),
        (Lifecycle.DEPRECATED, LifecycleAction.APPROVE),
    ],
)
def test_illegal_transitions(state: Lifecycle, action: LifecycleAction) -> None:
    with pytest.raises(InvalidStateError):
        next_state(state, action)


def test_version_validation() -> None:
    with pytest.raises(ValidationError):
        version_command("1.0")
    with pytest.raises(ValidationError):
        version_command("1.0.0-RC1")  # prerelease must be lowercase (identity names)
    with pytest.raises(ValidationError):
        version_command(digest="sha256:short")
    with pytest.raises(ValidationError):
        version_command().model_copy(update={}).model_validate(
            {**version_command().model_dump(), "scopes": ["Not A Scope"]}
        )


def test_egress_rules_normalise_and_flag_unrestricted() -> None:
    rule = EgressRule(cidr="10.0.0.0/8", ports=(443, 80, 443))
    assert rule.ports == (80, 443)
    assert not rule.unrestricted
    assert EgressRule(cidr="0.0.0.0/0", ports=(443,)).unrestricted
    assert EgressRule(cidr="::/0", ports=(443,)).unrestricted
    with pytest.raises(ValidationError):
        EgressRule(cidr="10.0.0.1/8", ports=(443,))  # host bits set
    with pytest.raises(ValidationError):
        EgressRule(cidr="10.0.0.0/8", ports=(70000,))


def test_agent_and_tool_commands_validate() -> None:
    with pytest.raises(ValidationError):
        agent_command(name="Bad Name")
    with pytest.raises(ValidationError):
        tool_command(name="X")
    with pytest.raises(ValidationError):
        tool_command().model_validate({**tool_command().model_dump(), "endpoint": "http://plain"})


def test_tool_schema_digest_is_canonical() -> None:
    a = ToolVersion.digest_of({"type": "object", "properties": {"a": {}, "b": {}}})
    b = ToolVersion.digest_of({"properties": {"b": {}, "a": {}}, "type": "object"})
    assert a == b
    assert a.startswith("sha256:")


def test_kill_switch_coverage() -> None:
    target = spec()
    other = spec("other-prod", ("billing", "billing-agent"))
    switch = KillSwitch(
        id="a" * 32,
        scope=KillScope.AGENT,
        target="claims/claims-triage",
        reason="investigation",
        engaged_by="secops@corp.test",
        engaged_at=NOW,
    )
    assert switch.covers(target)
    assert not switch.covers(other)
    by_deployment = switch.model_copy(
        update={"scope": KillScope.DEPLOYMENT, "target": "other-prod"}
    )
    assert by_deployment.covers(other)
    assert not by_deployment.covers(target)
    everything = switch.model_copy(update={"scope": KillScope.GLOBAL, "target": "*"})
    assert everything.covers(target)
    assert everything.covers(other)
    assert not everything.model_copy(update={"active": False}).covers(target)


def test_deployment_generations_and_identity_names() -> None:
    s = spec()
    assert s.next_generation == 1
    assert s.identity_name("1.2.3") == "claims-triage-prod-1.2.3"
    assert s.agent_key == "claims/claims-triage"


def test_with_approval_requires_review_state() -> None:
    from agent_control_plane.domain.models import AgentVersion

    version = AgentVersion(
        namespace="claims",
        name="claims-triage",
        created_by="dev",
        created_at=NOW,
        updated_at=NOW,
        **version_command().model_dump(),
    )
    with pytest.raises(InvalidStateError):
        version.with_approval(Approval(actor="a", at=NOW), at=NOW)
    reviewed = version.transition(LifecycleAction.SUBMIT, actor="dev", at=NOW)
    assert reviewed.submitted_by == "dev"
    approved_once = reviewed.with_approval(Approval(actor="a", at=NOW), at=NOW)
    assert len(approved_once.approvals) == 1
    rejected = approved_once.transition(LifecycleAction.REJECT, actor="b", at=NOW)
    assert rejected.state is Lifecycle.DRAFT
    assert rejected.approvals == ()
