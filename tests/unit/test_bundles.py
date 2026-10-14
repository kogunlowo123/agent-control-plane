"""Policy bundles: validated, normalised, digested, signed, immutable."""

from __future__ import annotations

import pytest
from agentic_core.policy import PolicyEngine, PolicyRequest, PolicySet, Resource, Subject

from agent_control_plane.application.bundles import BundleService, bundle_digest
from agent_control_plane.domain.errors import (
    ConflictError,
    ControlPlaneError,
    ForbiddenError,
    NotFoundError,
)
from agent_control_plane.runtime.container import Container
from agent_control_plane.security.signing import verify_digest
from tests.conftest import BUNDLE_POLICY, bundle_command, op


async def test_publish_signs_and_verifies(container: Container) -> None:
    bundle = await container.bundles.publish(bundle_command(), op(container, "policy@corp.test"))
    assert bundle.digest == bundle_digest(bundle.signed_payload())
    assert container.bundles.verify(bundle)
    key = container.bundles.signing_key()["keys"][0]
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert key["kid"] == bundle.key_id
    assert verify_digest(container.bundles._key.public, bundle.digest, bundle.signature)
    # Distributed policies evaluate as published.
    engine = PolicyEngine(PolicySet.model_validate(bundle.policies[0]))
    decision = engine.evaluate(
        PolicyRequest(
            subject=Subject(id="agent"),
            action="claims:pay:wire",
            resource=Resource(type="claim", attributes={"amount": 50_000}),
        )
    )
    assert decision.decision.value == "require_approval"


async def test_bundles_are_immutable_and_listed(container: Container) -> None:
    author = op(container, "policy@corp.test")
    await container.bundles.publish(bundle_command(), author)
    with pytest.raises(ConflictError):
        await container.bundles.publish(bundle_command(), author)
    await container.bundles.publish(bundle_command("1.1.0"), author)
    listed = await container.bundles.list(limit=10, offset=0)
    assert [b.key for b in listed] == ["claims-policy@1.0.0", "claims-policy@1.1.0"]
    assert (await container.bundles.get("claims-policy", "1.1.0")).version == "1.1.0"
    with pytest.raises(NotFoundError):
        await container.bundles.get("claims-policy", "9.9.9")


async def test_tampering_is_detected(container: Container) -> None:
    bundle = await container.bundles.publish(bundle_command(), op(container, "policy@corp.test"))
    altered = bundle.model_copy(
        update={"policies": ({**BUNDLE_POLICY, "rules": BUNDLE_POLICY["rules"][:1]},)}
    )
    assert not container.bundles.verify(altered)
    resigned = altered.model_copy(update={"digest": bundle_digest(altered.signed_payload())})
    assert not container.bundles.verify(resigned)  # signature no longer matches
    foreign = bundle.model_copy(update={"key_id": "someone-else"})
    assert not container.bundles.verify(foreign)


def test_invalid_policies_are_rejected() -> None:
    with pytest.raises(ControlPlaneError, match="not a valid policy set"):
        BundleService.normalise([{"name": "x", "version": "1", "rules": [{"id": "r"}]}])
    with pytest.raises(ControlPlaneError, match="appears twice"):
        BundleService.normalise([BUNDLE_POLICY, BUNDLE_POLICY])
    normalised = BundleService.normalise([BUNDLE_POLICY])
    assert normalised[0]["rules"][0]["resource_types"] == ["*"]  # defaults made explicit


async def test_only_policy_authors_publish(container: Container) -> None:
    with pytest.raises(ForbiddenError):
        await container.bundles.publish(bundle_command(), op(container, "deployer@corp.test"))
