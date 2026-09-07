"""Permission-tolerant, GET-only namespace and admission inventory."""

from __future__ import annotations

import re
from typing import Any

from .client import APIError, K8sClient
from .models import APIResource, PermissionKey


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

NEGATED_AUTHORIZER_CHECK = re.compile(
    r"""^\s*!\s*authorizer
        \.group\(\s*(?P<group_quote>['\"])(?P<group>[^'\"]*)(?P=group_quote)\s*\)
        \.resource\(\s*(?P<resource_quote>['\"])(?P<resource>[^'\"]+)(?P=resource_quote)\s*\)
        (?:\.namespace\(\s*(?P<namespace_quote>['\"])(?P<namespace>[^'\"]+)(?P=namespace_quote)\s*\))?
        \.name\(\s*(?P<name_quote>['\"])(?P<name>[^'\"]+)(?P=name_quote)\s*\)
        \.check\(\s*(?P<verb_quote>['\"])(?P<verb>[^'\"]+)(?P=verb_quote)\s*\)
        \.allowed\(\s*\)\s*$""",
    re.VERBOSE,
)


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

    _enrich_fail_open_webhook_targets(client, findings, unavailable)
    _enrich_validating_parameter_targets(client, findings, resources, unavailable)
    findings.extend(
        _collect_third_party_policy_objects(
            client, namespaces, resources, readable, unavailable
        )
    )
    return findings, readable, unavailable


def admission_sensitive_permissions(
    admission: list[dict[str, Any]],
) -> dict[PermissionKey, str]:
    """Return bounded exact checks derived from readable admission configuration."""
    result: dict[PermissionKey, str] = {}
    for item in admission:
        configuration = item.get("configuration") or {}
        condition_sets = [configuration.get("matchConditions") or []]
        for webhook in configuration.get("webhooks") or []:
            if isinstance(webhook, dict):
                condition_sets.append(webhook.get("matchConditions") or [])
        for conditions in condition_sets:
            for condition in conditions if isinstance(conditions, list) else []:
                if not isinstance(condition, dict):
                    continue
                expression = str(condition.get("expression") or "")
                # A false term skips a match condition only when it is the whole
                # expression or part of a plain conjunction. Do not infer through
                # OR/ternary CEL expressions.
                if "||" in expression or "?" in expression or ":" in expression:
                    continue
                for term in expression.split("&&"):
                    match = NEGATED_AUTHORIZER_CHECK.fullmatch(term.strip())
                    if not match:
                        continue
                    key = PermissionKey(
                        verb=match.group("verb"),
                        group=match.group("group"),
                        resource=match.group("resource"),
                        namespace=match.group("namespace") or "",
                        name=match.group("name"),
                    )
                    result[key] = (
                        f"Readable admission configuration {item.get('name')!r} contains "
                        f"a canonical negated authorizer check for {key.human()}; holding "
                        "this custom grant makes the conjunct false and skips that "
                        "policy or webhook."
                    )

        for target in configuration.get("failOpenTargets") or []:
            if not isinstance(target, dict) or target.get("exists") is not True:
                continue
            key = PermissionKey(
                verb="delete",
                resource="services",
                namespace=str(target.get("namespace") or ""),
                name=str(target.get("name") or ""),
            )
            result[key] = (
                f"Service {key.namespace}/{key.name} is the observed endpoint of a "
                f"failurePolicy=Ignore webhook in {item.get('name')!r}; deleting the "
                "Service makes webhook connection failures fail open."
            )
            backend = target.get("singleReadyDeployment") or {}
            if isinstance(backend, dict) and backend.get("name"):
                delete_key = PermissionKey(
                    verb="delete",
                    group="apps",
                    resource="deployments",
                    namespace=str(backend.get("namespace") or ""),
                    name=str(backend.get("name") or ""),
                )
                result[delete_key] = (
                    f"Deployment {delete_key.namespace}/{delete_key.name} is the "
                    "only observed ready backend for a failurePolicy=Ignore "
                    f"webhook in {item.get('name')!r}; deleting it makes webhook "
                    "connection failures fail open."
                )
                for verb in ("patch", "update"):
                    scale_key = PermissionKey(
                        verb=verb,
                        group="apps",
                        resource="deployments",
                        subresource="scale",
                        namespace=str(backend.get("namespace") or ""),
                        name=str(backend.get("name") or ""),
                    )
                    result[scale_key] = (
                        f"Deployment {scale_key.namespace}/{scale_key.name} is the "
                        "only observed ready backend for a failurePolicy=Ignore "
                        f"webhook in {item.get('name')!r}; scaling it to zero makes "
                        "webhook connection failures fail open."
                    )

        target = configuration.get("parameterTarget") or {}
        if not isinstance(target, dict) or target.get("exists") not in {True, False}:
            continue
        if not target.get("usedByDenyValidation"):
            continue
        base = {
            "group": str(target.get("group") or ""),
            "resource": str(target.get("resource") or ""),
            "namespace": str(target.get("namespace") or ""),
            "name": str(target.get("name") or ""),
        }
        verbs: list[str] = []
        if target["exists"] is True:
            verbs.extend(("update", "patch"))
            if target.get("parameterNotFoundAction") == "Allow":
                verbs.append("delete")
        elif target.get("parameterNotFoundAction") == "Deny":
            verbs.append("create")
        for verb in verbs:
            key = PermissionKey(verb=verb, **base)
            result[key] = (
                f"This exact object is a parameter for enforced ValidatingAdmissionPolicy "
                f"binding {item.get('name')!r}; {verb} can change or remove the parameter "
                "and alter whether matching requests are admitted."
            )
    return result


def _enrich_fail_open_webhook_targets(
    client: K8sClient,
    findings: list[dict[str, Any]],
    unavailable: list[str],
) -> None:
    """Correlate fail-open webhooks with existing Services and sole backends."""
    for item in findings:
        if item.get("type") not in {"mutating webhooks", "validating webhooks"}:
            continue
        configuration = item.get("configuration") or {}
        targets: list[dict[str, Any]] = []
        for webhook in configuration.get("webhooks") or []:
            if not isinstance(webhook, dict) or webhook.get("failurePolicy") != "Ignore":
                continue
            service_ref = (webhook.get("clientConfig") or {}).get("service") or {}
            namespace = str(service_ref.get("namespace") or "")
            name = str(service_ref.get("name") or "")
            if not is_valid_namespace_name(namespace) or not is_valid_namespace_name(name):
                continue
            try:
                service = client.get(f"/api/v1/namespaces/{namespace}/services/{name}")
            except APIError as exc:
                if exc.status != 404:
                    unavailable.append(f"fail-open webhook Service {namespace}/{name}: {exc}")
                continue
            target: dict[str, Any] = {
                "namespace": namespace,
                "name": name,
                "exists": True,
                "webhook": str(webhook.get("name") or ""),
            }
            backend = _single_ready_deployment_backend(client, namespace, name, service)
            if backend:
                target["singleReadyDeployment"] = backend
            targets.append(target)
        if targets:
            configuration["failOpenTargets"] = targets


def _single_ready_deployment_backend(
    client: K8sClient,
    namespace: str,
    service_name: str,
    service: dict[str, Any],
) -> dict[str, str] | None:
    selector = (service.get("spec") or {}).get("selector") or {}
    if not isinstance(selector, dict) or not selector:
        return None
    try:
        slices = client.list_items(
            f"/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices"
        )
        pods = client.list_items(f"/api/v1/namespaces/{namespace}/pods")
        replicasets = client.list_items(
            f"/apis/apps/v1/namespaces/{namespace}/replicasets"
        )
        deployments = client.list_items(
            f"/apis/apps/v1/namespaces/{namespace}/deployments"
        )
    except APIError:
        return None

    ready_names: set[str] = set()
    for endpoint_slice in slices:
        labels = (endpoint_slice.get("metadata") or {}).get("labels") or {}
        if labels.get("kubernetes.io/service-name") != service_name:
            continue
        for endpoint in endpoint_slice.get("endpoints") or []:
            if (endpoint.get("conditions") or {}).get("ready") is False:
                continue
            ref = endpoint.get("targetRef") or {}
            if ref.get("kind") != "Pod" or ref.get("namespace", namespace) != namespace:
                return None
            ready_names.add(str(ref.get("name") or ""))
    if not ready_names or "" in ready_names:
        return None

    pod_by_name = {
        str((pod.get("metadata") or {}).get("name") or ""): pod for pod in pods
    }
    rs_by_name = {
        str((rs.get("metadata") or {}).get("name") or ""): rs for rs in replicasets
    }
    deployment_owners_seen: set[tuple[str, str]] = set()
    for pod_name in ready_names:
        pod = pod_by_name.get(pod_name)
        labels = ((pod or {}).get("metadata") or {}).get("labels") or {}
        if pod is None or any(labels.get(key) != value for key, value in selector.items()):
            return None
        owners = (pod.get("metadata") or {}).get("ownerReferences") or []
        rs_owners = [
            owner
            for owner in owners
            if owner.get("kind") == "ReplicaSet" and owner.get("controller")
        ]
        if len(rs_owners) != 1:
            return None
        replica_set = rs_by_name.get(str(rs_owners[0].get("name") or ""))
        rs_metadata = (replica_set or {}).get("metadata") or {}
        if replica_set is None or str(rs_owners[0].get("uid") or "") != str(
            rs_metadata.get("uid") or ""
        ):
            return None
        deployment_owners = [
            owner
            for owner in (rs_metadata.get("ownerReferences") or [])
            if owner.get("kind") == "Deployment" and owner.get("controller")
        ]
        if len(deployment_owners) != 1:
            return None
        deployment_owners_seen.add(
            (
                str(deployment_owners[0].get("name") or ""),
                str(deployment_owners[0].get("uid") or ""),
            )
        )
    if len(deployment_owners_seen) != 1:
        return None
    deployment_name, deployment_uid = next(iter(deployment_owners_seen))
    deployment = next(
        (
            value
            for value in deployments
            if str((value.get("metadata") or {}).get("name") or "") == deployment_name
        ),
        None,
    )
    if (
        deployment is None
        or str((deployment.get("metadata") or {}).get("uid") or "") != deployment_uid
        or int((deployment.get("spec") or {}).get("replicas") or 0) < 1
    ):
        return None
    return {"namespace": namespace, "name": deployment_name}


def _enrich_validating_parameter_targets(
    client: K8sClient,
    findings: list[dict[str, Any]],
    resources: list[APIResource],
    unavailable: list[str],
) -> None:
    policies = {
        str(item.get("name") or ""): item.get("configuration") or {}
        for item in findings
        if item.get("type") == "validating admission policies"
    }
    for binding in findings:
        if binding.get("type") != "validating admission policy bindings":
            continue
        configuration = binding.get("configuration") or {}
        actions = configuration.get("validationActions") or []
        if "Deny" not in actions:
            continue
        policy = policies.get(str(configuration.get("policyName") or "")) or {}
        param_kind = policy.get("paramKind") or {}
        param_ref = configuration.get("paramRef") or {}
        if not isinstance(param_kind, dict) or not isinstance(param_ref, dict):
            continue
        if not param_ref.get("name") or param_ref.get("selector"):
            continue
        expressions = str(
            policy.get("validations") or []
        ) + str(policy.get("matchConditions") or [])
        if "params" not in expressions:
            continue
        api_version = str(param_kind.get("apiVersion") or "")
        if "/" in api_version:
            group, version = api_version.rsplit("/", 1)
        else:
            group, version = "", api_version
        kind = str(param_kind.get("kind") or "")
        resource = next(
            (
                item
                for item in resources
                if not item.subresource
                and item.group == group
                and item.version == version
                and item.kind.casefold() == kind.casefold()
            ),
            None,
        )
        if resource is None:
            continue
        namespace = str(param_ref.get("namespace") or "")
        if resource.namespaced and not namespace:
            continue
        name = str(param_ref["name"])
        base = f"/apis/{group}/{version}" if group else f"/api/{version}"
        if resource.namespaced:
            path = f"{base}/namespaces/{namespace}/{resource.resource}/{name}"
        else:
            path = f"{base}/{resource.resource}/{name}"
        exists: bool | None
        try:
            client.get(path)
            exists = True
        except APIError as exc:
            exists = False if exc.status == 404 else None
            if exists is None:
                unavailable.append(
                    f"parameter target for {binding.get('name')}: {exc}"
                )
        configuration["parameterTarget"] = {
            "group": group,
            "version": version,
            "resource": resource.resource,
            "namespace": namespace,
            "name": name,
            "exists": exists,
            "parameterNotFoundAction": param_ref.get("parameterNotFoundAction"),
            "usedByDenyValidation": True,
        }


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
        "paramRef",
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
