"""Drift detection between rendered desired objects and live cluster objects.

The API server adds defaults and bookkeeping (``status``, ``resourceVersion``,
``dnsPolicy``, ``defaultMode`` ...), so a naive equality check reports drift
forever. The comparison is therefore a *subset* check: every field the
control plane renders must be present with the rendered value. Three rules
tighten it where an addition, not just a change, is a security event:

1. Lists of named items (containers, env, volumes, ports) are matched by
   name, and named items present only in the cluster are reported as
   ``unexpected`` (an injected sidecar or an extra environment variable).
2. Paths in ``STRICT_PATHS`` are compared exactly: extra keys are drift
   (security contexts, NetworkPolicy spec, ConfigMap data).
3. Pod-level host namespaces and privileged containers are always drift.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent_control_plane.domain.models import DriftItem
from agent_control_plane.domain.ports import Manifest

STRICT_PATHS = (
    re.compile(r"^spec\.template\.spec\.securityContext$"),
    re.compile(r"^spec\.template\.spec\.containers\[[^\]]+\]\.securityContext$"),
    re.compile(r"^spec\.template\.spec\.containers\[[^\]]+\]\.resources$"),
    re.compile(r"^spec\.ingress$"),
    re.compile(r"^spec\.egress$"),
    re.compile(r"^data$"),
)
HOST_FIELDS = ("hostNetwork", "hostPID", "hostIPC")


def _strict(path: str) -> bool:
    return any(p.fullmatch(path) for p in STRICT_PATHS)


def _named(items: list[Any]) -> bool:
    return bool(items) and all(isinstance(i, dict) and "name" in i for i in items)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


@dataclass(frozen=True)
class _Where:
    kind: str
    name: str

    def item(self, path: str, change: str, expected: Any = None, actual: Any = None) -> DriftItem:
        return DriftItem(
            kind=self.kind,
            name=self.name,
            path=path,
            change=change,
            expected=expected,
            actual=actual,
        )


def diff(desired: Any, actual: Any, *, kind: str, name: str, path: str = "") -> list[DriftItem]:
    """Differences between a desired fragment and the live fragment at ``path``."""
    where = _Where(kind, name)
    if isinstance(desired, dict):
        if not isinstance(actual, dict):
            return [where.item(path, "changed", desired, actual)]
        return _diff_mapping(desired, actual, where, path)
    if isinstance(desired, list):
        if not isinstance(actual, list):
            return [where.item(path, "changed", desired, actual)]
        return _diff_list(desired, actual, where, path)
    return [] if desired == actual else [where.item(path, "changed", desired, actual)]


def _diff_mapping(
    desired: dict[str, Any], actual: dict[str, Any], where: _Where, path: str
) -> list[DriftItem]:
    items: list[DriftItem] = []
    for key, value in desired.items():
        child = _join(path, key)
        if actual.get(key) is None:
            # The API server omits empty collections (omitempty) on the wire.
            if value not in ([], {}, None):
                items.append(where.item(child, "missing", value))
        else:
            items += diff(value, actual[key], kind=where.kind, name=where.name, path=child)
    if _strict(path):
        items += [
            where.item(_join(path, key), "unexpected", None, actual[key])
            for key in sorted(set(actual) - set(desired))
        ]
    return items


def _diff_list(desired: list[Any], actual: list[Any], where: _Where, path: str) -> list[DriftItem]:
    if _named(desired) and all(isinstance(i, dict) and "name" in i for i in actual):
        by_name = {i["name"]: i for i in actual}
        items: list[DriftItem] = []
        for entry in desired:
            child = f"{path}[{entry['name']}]"
            live = by_name.get(entry["name"])
            if live is None:
                items.append(where.item(child, "missing", entry))
            else:
                items += diff(entry, live, kind=where.kind, name=where.name, path=child)
        wanted = {i["name"] for i in desired}
        items += [
            where.item(f"{path}[{extra}]", "unexpected", None, by_name[extra])
            for extra in sorted(set(by_name) - wanted)
        ]
        return items
    if len(desired) != len(actual):
        return [where.item(path, "changed", desired, actual)]
    items = []
    for index, (want, have) in enumerate(zip(desired, actual, strict=True)):
        items += diff(want, have, kind=where.kind, name=where.name, path=f"{path}[{index}]")
    return items


def _host_escalations(kind: str, name: str, actual: Manifest) -> list[DriftItem]:
    if kind != "Deployment":
        return []
    pod = actual.get("spec", {}).get("template", {}).get("spec", {})
    found = [
        DriftItem(
            kind=kind,
            name=name,
            path=f"spec.template.spec.{field}",
            change="unexpected",
            expected=None,
            actual=pod[field],
        )
        for field in HOST_FIELDS
        if pod.get(field)
    ]
    for group in ("initContainers", "ephemeralContainers"):
        for container in pod.get(group) or []:
            found.append(
                DriftItem(
                    kind=kind,
                    name=name,
                    path=f"spec.template.spec.{group}[{container.get('name', '?')}]",
                    change="unexpected",
                    expected=None,
                    actual=container.get("image"),
                )
            )
    return found


def detect(desired: Manifest, actual: Manifest | None) -> list[DriftItem]:
    """Drift for one object; an absent object is a single ``absent`` item."""
    kind = desired["kind"]
    name = desired["metadata"]["name"]
    if actual is None:
        return [DriftItem(kind=kind, name=name, path="", change="absent")]
    tracked = {k: v for k, v in desired.items() if k not in {"apiVersion", "kind"}}
    observed = {k: actual[k] for k in tracked if k in actual}
    return diff(tracked, observed, kind=kind, name=name) + _host_escalations(kind, name, actual)
