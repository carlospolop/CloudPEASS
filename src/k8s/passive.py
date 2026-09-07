"""Permission-tolerant, GET-only namespace and admission inventory."""

from __future__ import annotations

import re
from typing import Any

from .client import APIError, K8sClient
from .models import APIResource


ADMISSION_LISTS = {
    "mutating webhooks": (
        "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"
    ),
    "validating webhooks": (
        "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"
    ),
    "validating admission policies": (
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"
    ),
    "validating admission policy bindings": (
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"
    ),
    "mutating admission policies": (
        "/apis/admissionregistration.k8s.io/v1alpha1/mutatingadmissionpolicies"
    ),
    "mutating admission policy bindings": (
        "/apis/admissionregistration.k8s.io/v1alpha1/mutatingadmissionpolicybindings"
    ),
}

ADMISSION_LABELS = {
    "mutatingwebhookconfigurations": "mutating webhooks",
    "validatingwebhookconfigurations": "validating webhooks",
    "validatingadmissionpolicies": "validating admission policies",
    "validatingadmissionpolicybindings": "validating admission policy bindings",
    "mutatingadmissionpolicies": "mutating admission policies",
    "mutatingadmissionpolicybindings": "mutating admission policy bindings",
}

NAMESPACE_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")


def is_valid_namespace_name(name: str) -> bool:
    return bool(NAMESPACE_NAME_PATTERN.fullmatch(name))


def discover_namespaces(
    client: K8sClient,
    initial: list[str],
) -> tuple[list[str], list[dict[str, Any]], str]:
    namespaces = {name for name in initial if is_valid_namespace_name(name)}
    try:
        items = client.list_items("/api/v1/namespaces")
    except APIError as exc:
        items = []
        for name in sorted(namespaces):
            try:
                items.append(client.get(f"/api/v1/namespaces/{name}"))
            except APIError:
                continue
        return sorted(namespaces), items, str(exc)
    for item in items:
        name = ((item.get("metadata") or {}).get("name") or "")
        if is_valid_namespace_name(name):
            namespaces.add(name)
    return sorted(namespaces), items, ""


def analyze_admission_read_only(
    client: K8sClient,
    namespace_objects: list[dict[str, Any]],
    namespaces: list[str],
    resources: list[APIResource],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Inspect readable admission objects; never submit candidate writes."""
    findings: list[dict[str, Any]] = []
    readable: list[str] = []
    unavailable: list[str] = []

    for namespace in namespace_objects:
        metadata = namespace.get("metadata") or {}
        labels = metadata.get("labels") or {}
        psa = {
            key: value
            for key, value in labels.items()
            if str(key).startswith("pod-security.kubernetes.io/")
        }
        if psa:
            findings.append(
                {
                    "type": "Pod Security Admission namespace labels",
                    "name": metadata.get("name") or "",
                    "scope": "namespace",
                    "configuration": psa,
                    "meaning": (
                        "These labels may enforce, warn, or audit Pod Security levels. "
                        "No write request was sent to test them."
                    ),
                    "confidence": "configuration-observed",
                }
            )

    for label, path in _served_admission_lists(resources).items():
        try:
            items = client.list_items(path)
        except APIError as exc:
            unavailable.append(f"{label}: {exc}")
            continue
        readable.append(label)
        for item in items:
            metadata = item.get("metadata") or {}
            findings.append(
                {
                    "type": label,
                    "name": metadata.get("name") or "",
                    "scope": "cluster",
                    "configuration": _summarize_admission_object(item),
                    "observations": _admission_observations(item),
                    "meaning": (
                        "Readable policy configuration only. Effective behavior remains "
                        "unknown without a write, which K8sPEASS never performs."
                    ),
                    "confidence": "configuration-observed",
                }
            )

    for namespace in namespaces:
        for kind, path in (
            ("LimitRanges", f"/api/v1/namespaces/{namespace}/limitranges"),
            ("ResourceQuotas", f"/api/v1/namespaces/{namespace}/resourcequotas"),
        ):
            try:
                items = client.list_items(path)
            except APIError as exc:
                unavailable.append(f"{kind} in {namespace}: {exc}")
                continue
            readable.append(f"{kind} in {namespace}")
            for item in items:
                findings.append(
                    {
                        "type": kind,
                        "name": (item.get("metadata") or {}).get("name") or "",
                        "scope": namespace,
                        "configuration": item.get("spec") or {},
                        "meaning": (
                            "This built-in admission configuration may default or reject "
                            "workloads. It was read only; no candidate was submitted."
                        ),
                        "confidence": "configuration-observed",
                    }
                )

    findings.extend(
        _collect_third_party_policy_objects(
            client, namespaces, resources, readable, unavailable
        )
    )
    return findings, readable, unavailable


def _served_admission_lists(resources: list[APIResource]) -> dict[str, str]:
    """Use discovered versions so alpha/beta/stable API transitions do not break us."""
    candidates: dict[str, list[APIResource]] = {}
    for resource in resources:
        if (
            resource.group == "admissionregistration.k8s.io"
            and not resource.subresource
            and resource.resource in ADMISSION_LABELS
            and "list" in resource.verbs
        ):
            candidates.setdefault(resource.resource, []).append(resource)
    if not candidates:
        return ADMISSION_LISTS.copy()

    result: dict[str, str] = {}
    for resource_name, versions in candidates.items():
        selected = sorted(versions, key=lambda item: _version_rank(item.version))[0]
        label = ADMISSION_LABELS[resource_name]
        result[label] = (
            f"/apis/{selected.group}/{selected.version}/{selected.resource}"
        )
    return result


def _version_rank(version: str) -> tuple[int, int, str]:
    if version.startswith("v") and version[1:].isdigit():
        return (0, -int(version[1:]), version)
    if "beta" in version:
        return (1, 0, version)
    return (2, 0, version)


def _collect_third_party_policy_objects(
    client: K8sClient,
    namespaces: list[str],
    resources: list[APIResource],
    readable: list[str],
    unavailable: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    keywords = ("policy", "exception", "constraint", "assign", "admission")
    groups = ("kyverno", "gatekeeper")
    seen: set[tuple[str, str, str]] = set()
    for resource in resources:
        if resource.subresource:
            continue
        if not any(group in resource.group.lower() for group in groups):
            continue
        if not any(word in resource.resource.lower() for word in keywords):
            continue
        identity = (resource.group, resource.version, resource.resource)
        if identity in seen:
            continue
        seen.add(identity)
        base = f"/apis/{resource.group}/{resource.version}"
        scopes = namespaces if resource.namespaced else [""]
        for namespace in scopes:
            if namespace:
                path = f"{base}/namespaces/{namespace}/{resource.resource}"
                label = f"{resource.api_name} in {namespace}"
            else:
                path = f"{base}/{resource.resource}"
                label = resource.api_name
            try:
                items = client.list_items(path)
            except APIError as exc:
                unavailable.append(f"{label}: {exc}")
                continue
            readable.append(label)
            for item in items:
                findings.append(
                    {
                        "type": f"third-party policy ({resource.group})",
                        "name": (item.get("metadata") or {}).get("name") or "",
                        "scope": namespace or "cluster",
                        "configuration": item.get("spec") or {},
                        "observations": _admission_observations(item),
                        "meaning": (
                            "Third-party policy configuration was readable. Enforcement "
                            "cannot be proven without a write, which was not attempted."
                        ),
                        "confidence": "configuration-observed",
                    }
                )
    return findings


def _summarize_admission_object(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec") or {}
    keep = {
        "failurePolicy",
        "matchConstraints",
        "matchConditions",
        "matchResources",
        "paramKind",
        "policyName",
        "validationActions",
        "validations",
        "mutations",
        "reinvocationPolicy",
    }
    summary = {key: value for key, value in spec.items() if key in keep}
    if "webhooks" in item:
        summary["webhooks"] = item["webhooks"]
    return summary or {"note": "No summarized fields were present."}


def _admission_observations(item: dict[str, Any]) -> list[str]:
    """Explain common enforcement gaps without claiming a bypass is exploitable."""
    observations: list[str] = []
    spec = item.get("spec") or {}
    webhooks = item.get("webhooks") or []
    entries = webhooks if isinstance(webhooks, list) else []
    if spec:
        entries = entries + [spec]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or item.get("kind") or "policy")
        if entry.get("failurePolicy") == "Ignore":
            observations.append(f"{name}: failurePolicy=Ignore can fail open.")
        if entry.get("namespaceSelector"):
            observations.append(f"{name}: namespaceSelector limits matching namespaces.")
        if entry.get("objectSelector"):
            observations.append(f"{name}: objectSelector limits matching objects.")
        if entry.get("matchConditions"):
            observations.append(f"{name}: matchConditions may exclude some requests.")
        actions = {str(value) for value in (entry.get("validationActions") or [])}
        if actions and "Deny" not in actions:
            observations.append(
                f"{name}: validationActions={sorted(actions)} does not include Deny."
            )
    return sorted(set(observations))
