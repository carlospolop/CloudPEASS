"""Kubernetes API discovery with partial-result tolerance."""

from __future__ import annotations

from .client import APIError, K8sClient
from .models import APIResource


def discover_api_resources(
    client: K8sClient,
) -> tuple[list[APIResource], list[str]]:
    """Return every discoverable resource and non-fatal discovery warnings."""
    warnings: list[str] = []
    group_versions: set[str] = set()

    try:
        core = client.get("/api")
        group_versions.update(
            f"core/{version}" for version in (core.get("versions") or [])
        )
    except APIError as exc:
        warnings.append(f"Core API discovery failed: {exc}")

    try:
        groups = client.get("/apis")
        for group in groups.get("groups") or []:
            for version in group.get("versions") or []:
                group_version = version.get("groupVersion")
                if group_version:
                    group_versions.add(group_version)
    except APIError as exc:
        warnings.append(f"Grouped API discovery failed: {exc}")

    resources: list[APIResource] = []
    for group_version in sorted(group_versions):
        if group_version.startswith("core/"):
            group = ""
            version = group_version.split("/", 1)[1]
            path = f"/api/{version}"
        else:
            group, version = group_version.rsplit("/", 1)
            path = f"/apis/{group_version}"
        try:
            resource_list = client.get(path)
        except APIError as exc:
            warnings.append(f"Discovery failed for {group_version}: {exc}")
            continue
        for item in resource_list.get("resources") or []:
            name = str(item.get("name") or "")
            if not name:
                continue
            parent, _, subresource = name.partition("/")
            resources.append(
                APIResource(
                    group=group,
                    version=version,
                    resource=parent,
                    subresource=subresource,
                    namespaced=bool(item.get("namespaced")),
                    verbs=tuple(sorted(str(v) for v in (item.get("verbs") or []))),
                    kind=str(item.get("kind") or ""),
                )
            )

    unique = {
        (
            item.group,
            item.version,
            item.resource,
            item.subresource,
            item.namespaced,
        ): item
        for item in resources
    }
    result = sorted(
        unique.values(),
        key=lambda r: (
            not r.namespaced,
            r.group,
            r.resource,
            r.subresource,
            r.version,
        ),
    )
    return result, warnings
