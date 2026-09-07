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
        versions = core.get("versions") or []
        if not isinstance(versions, list):
            warnings.append("Core API discovery returned a non-array versions field")
            versions = []
        group_versions.update(
            f"core/{version}" for version in versions if isinstance(version, str)
        )
    except APIError as exc:
        warnings.append(f"Core API discovery failed: {exc}")

    try:
        groups = client.get("/apis")
        group_items = groups.get("groups") or []
        if not isinstance(group_items, list):
            warnings.append("Grouped API discovery returned a non-array groups field")
            group_items = []
        for group in group_items:
            if not isinstance(group, dict):
                warnings.append("Grouped API discovery contained a malformed group")
                continue
            versions = group.get("versions") or []
            if not isinstance(versions, list):
                warnings.append("Grouped API discovery contained malformed versions")
                continue
            for version in versions:
                if not isinstance(version, dict):
                    warnings.append("Grouped API discovery contained a malformed version")
                    continue
                group_version = version.get("groupVersion")
                if isinstance(group_version, str) and "/" in group_version:
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
        resource_items = resource_list.get("resources") or []
        if not isinstance(resource_items, list):
            warnings.append(f"Discovery returned malformed resources for {group_version}")
            continue
        for item in resource_items:
            if not isinstance(item, dict):
                warnings.append(f"Discovery returned a malformed resource for {group_version}")
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            parent, _, subresource = name.partition("/")
            verbs = item.get("verbs") or []
            if not isinstance(verbs, list):
                warnings.append(
                    f"Discovery returned malformed verbs for {group_version}/{name}"
                )
                verbs = []
            resources.append(
                APIResource(
                    group=group,
                    version=version,
                    resource=parent,
                    subresource=subresource,
                    namespaced=bool(item.get("namespaced")),
                    verbs=tuple(sorted(str(v) for v in verbs)),
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
