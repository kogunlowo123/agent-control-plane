"""Policy bundle publication and distribution.

A bundle is an immutable, versioned set of agentic-core ``PolicySet``
documents. Each policy is parsed and normalised on publication (so an
invalid rule never reaches an agent), the bundle is digested over its
canonical JSON, and the digest is signed with the control plane's Ed25519
bundle key. Agents and gateways receive the bundle through the ConfigMap
the reconciler mounts into each workload and verify it against the public
key published at ``/v1/policy-bundles/signing-key``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agentic_core.domain.provenance import canonical_json, content_digest
from agentic_core.policy import PolicySet
from agentic_core.policy import Resource as PolicyResource
from pydantic import ValidationError

from agent_control_plane.application.commands import PublishBundle
from agent_control_plane.application.governance import Caller, Governance
from agent_control_plane.domain.errors import ControlPlaneError, NotFoundError
from agent_control_plane.domain.models import PolicyBundle
from agent_control_plane.domain.ports import BundleRepository, Clock
from agent_control_plane.security.content import TextScreen
from agent_control_plane.security.signing import SigningKey, sign_digest, verify_digest


def bundle_digest(payload: dict[str, Any]) -> str:
    return content_digest(canonical_json(payload))


class BundleService:
    def __init__(
        self,
        *,
        bundles: BundleRepository,
        key: SigningKey,
        governance: Governance,
        screen: TextScreen,
        clock: Clock,
    ) -> None:
        self._bundles = bundles
        self._key = key
        self._gov = governance
        self._screen = screen
        self._clock = clock

    @staticmethod
    def normalise(policies: Sequence[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
        normalised: list[dict[str, Any]] = []
        names: set[str] = set()
        for index, document in enumerate(policies):
            try:
                policy = PolicySet.model_validate(document)
            except ValidationError as exc:
                first = exc.errors()[0]
                where = ".".join(str(p) for p in first.get("loc", ()))
                raise ControlPlaneError(
                    f"policies[{index}] is not a valid policy set: {where} {first.get('msg')}"
                ) from exc
            if policy.name in names:
                raise ControlPlaneError(f"policy set {policy.name!r} appears twice in the bundle")
            names.add(policy.name)
            normalised.append(policy.model_dump(mode="json"))
        return tuple(normalised)

    async def publish(self, command: PublishBundle, caller: Caller) -> PolicyBundle:
        key = f"{command.name}@{command.version}"
        decided = await self._gov.check(
            caller,
            action="controlplane:bundle:publish",
            resource=PolicyResource(type="policy_bundle", id=key),
        )
        policies = self.normalise(command.policies)
        description = self._screen.free_text("description", command.description)
        payload = {
            "name": command.name,
            "version": command.version,
            "description": description,
            "policies": list(policies),
        }
        digest = bundle_digest(payload)
        bundle = PolicyBundle(
            name=command.name,
            version=command.version,
            description=description,
            policies=policies,
            digest=digest,
            signature=sign_digest(self._key, digest),
            key_id=self._key.key_id,
            published_by=decided.subject,
            published_at=self._clock.now(),
        )
        await self._bundles.add(bundle)
        await self._gov.recorder.record(
            decided.subject,
            "policy_bundle.publish",
            f"policy_bundle:{key}",
            "success",
            {
                "digest": digest,
                "key_id": bundle.key_id,
                "policy_sets": sorted(str(p["name"]) for p in policies),
            },
        )
        return bundle

    async def get(self, name: str, version: str) -> PolicyBundle:
        bundle = await self._bundles.get(name, version)
        if bundle is None:
            raise NotFoundError(f"policy bundle {name}@{version} not found")
        return bundle

    async def list(self, *, limit: int, offset: int) -> Sequence[PolicyBundle]:
        return await self._bundles.list(limit=limit, offset=offset)

    def verify(self, bundle: PolicyBundle) -> bool:
        """True when the stored digest matches the content and the signature is ours."""
        if bundle_digest(bundle.signed_payload()) != bundle.digest:
            return False
        if bundle.key_id != self._key.key_id:
            return False
        return verify_digest(self._key.public, bundle.digest, bundle.signature)

    def signing_key(self) -> dict[str, Any]:
        return {"keys": [self._key.jwk()]}
