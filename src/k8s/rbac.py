"""GET-only RBAC inventory and explanation."""

from __future__ import annotations

from typing import Any

from .client import APIError, K8sClient


def collect_rbac_explanations(
    client: K8sClient,
    identity: dict[str, Any],
    namespaces: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    readable: list[str] = []
    unavailable: list[str] = []
    cluster_roles = _read(
        client,
        "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "clusterroles",
        readable,
        unavailable,
    )
    cluster_bindings = _read(
        client,
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "clusterrolebindings",
        readable,
        unavailable,
    )
    roles: dict[tuple[str, str], dict[str, Any]] = {}
    role_bindings: list[dict[str, Any]] = []
    for namespace in namespaces:
        for item in _read(
            client,
            f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles",
            f"roles in {namespace}",
            readable,
            unavailable,
        ):
            name = str((item.get("metadata") or {}).get("name") or "")
            roles[(namespace, name)] = item
        role_bindings.extend(
            _read(
                client,
                f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings",
                f"rolebindings in {namespace}",
                readable,
                unavailable,
            )
        )

    cluster_role_map = {
        str((item.get("metadata") or {}).get("name") or ""): item
        for item in cluster_roles
    }
    explanations: list[dict[str, Any]] = []
    for binding in cluster_bindings + role_bindings:
        subjects = binding.get("subjects") or []
        matched = [
            subject for subject in subjects if _subject_matches(subject, identity)
        ]
        if not matched:
            continue
        metadata = binding.get("metadata") or {}
        namespace = str(metadata.get("namespace") or "")
        role_ref = binding.get("roleRef") or {}
        role_kind = str(role_ref.get("kind") or "")
        role_name = str(role_ref.get("name") or "")
        if role_kind == "Role":
            role = roles.get((namespace, role_name), {})
        else:
            role = cluster_role_map.get(role_name, {})
        explanations.append(
            {
                "binding_kind": binding.get("kind") or "",
                "binding_name": metadata.get("name") or "",
                "namespace": namespace,
                "matched_subjects": matched,
                "role_ref": role_ref,
                "rules": role.get("rules") or [],
                "aggregation_rule": role.get("aggregationRule") or {},
                "confidence": "rbac-objects-observed",
            }
        )
    return explanations, readable, unavailable


def _read(
    client: K8sClient,
    path: str,
    label: str,
    readable: list[str],
    unavailable: list[str],
) -> list[dict[str, Any]]:
    try:
        items = client.list_items(path)
    except APIError as exc:
        unavailable.append(f"{label}: {exc}")
        return []
    readable.append(label)
    return items


def _subject_matches(subject: dict[str, Any], identity: dict[str, Any]) -> bool:
    kind = str(subject.get("kind") or "")
    name = str(subject.get("name") or "")
    username = str(identity.get("username") or "")
    groups = {str(group) for group in (identity.get("groups") or [])}
    if kind == "User":
        return name == username
    if kind == "Group":
        return name in groups
    if kind == "ServiceAccount":
        namespace = str(subject.get("namespace") or "")
        return username == f"system:serviceaccount:{namespace}:{name}"
    return False
