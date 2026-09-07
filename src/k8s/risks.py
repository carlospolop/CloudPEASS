"""Plain-language Kubernetes permission risk classification.

Ratings represent the highest realistic offensive impact of a granted RBAC
rule. They do not claim that a target exists or that admission, resourceNames,
selectors, or another authorizer will permit the complete attack chain.
"""

from __future__ import annotations

from .models import PermissionKey


READ_VERBS = {"get", "list", "watch"}
CHANGE_VERBS = {"create", "update", "patch", "*"}
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*"}

WORKLOADS = {
    "pods",
    "deployments",
    "daemonsets",
    "statefulsets",
    "replicasets",
    "replicationcontrollers",
    "jobs",
    "cronjobs",
}

RBAC_RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}

ADMISSION_RESOURCES = {
    "mutatingwebhookconfigurations",
    "validatingwebhookconfigurations",
    "mutatingadmissionpolicies",
    "mutatingadmissionpolicybindings",
    "validatingadmissionpolicies",
    "validatingadmissionpolicybindings",
}

STORAGE_CONTROL_RESOURCES = {"persistentvolumes"}

POLICY_REPORT_RESOURCES = {
    "admissionreports",
    "backgroundscanreports",
    "clusteradmissionreports",
    "clusterbackgroundscanreports",
    "clusterpolicyreports",
    "policyreports",
}

MEDIUM_READ_RESOURCES = WORKLOADS | {
    "configmaps",
    "pods",
    "nodes",
    "serviceaccounts",
    "roles",
    "clusterroles",
    "rolebindings",
    "clusterrolebindings",
    "persistentvolumes",
    "persistentvolumeclaims",
    "services",
    "endpoints",
    "endpointslices",
    "ingresses",
}

CORE_GROUPS = {"", "*"}


def _group_is(group: str, *expected: str) -> bool:
    return group == "*" or group in expected


def _is_workload(group: str, resource: str) -> bool:
    if resource in {"pods", "replicationcontrollers"}:
        return _group_is(group, "")
    if resource in {"deployments", "daemonsets", "statefulsets", "replicasets"}:
        return _group_is(group, "apps")
    if resource in {"jobs", "cronjobs"}:
        return _group_is(group, "batch")
    return False


def _is_write_verb(verb: str) -> bool:
    """Include Kubernetes special mutation verbs that discovery can advertise."""
    return (
        verb in WRITE_VERBS
        or verb == "unsafe-delete-ignore-read-errors"
        or verb.endswith((":patch", ":update"))
    )


def classify_permission(key: PermissionKey) -> tuple[str, str]:
    verb = key.verb.lower()
    resource = key.resource.lower()
    subresource = key.subresource.lower()
    group = key.group.lower()
    full = f"{resource}/{subresource}" if subresource else resource

    if key.non_resource_url:
        path = key.non_resource_url.lower()
        if path in {"/api", "/api/*", "/apis", "/apis/*", "/version", "/openapi/*"}:
            return "low", "Basic API discovery access."
        if path.startswith(("/debug", "/logs")) or "*" in path:
            return "high", f"Can access sensitive API-server path {key.non_resource_url}."
        if path.startswith("/metrics"):
            return "medium", "Can read API-server metrics and operational metadata."
        return "low", f"Can access API-server path {key.non_resource_url}."

    if resource == "*":
        if (verb in READ_VERBS or verb == "*") and group in CORE_GROUPS:
            return "critical", "Can read every current and future API resource, including Secrets."
        if verb in READ_VERBS or verb == "*":
            return "medium", f"Can read every current and future resource in API group {group}."
        if verb in CHANGE_VERBS and group in {
            "",
            "*",
            "apps",
            "batch",
            "admissionregistration.k8s.io",
            "certificates.k8s.io",
            "discovery.k8s.io",
        }:
            return "high", "Can change every current and future API resource allowed by this scope."
    if resource == "secrets" and group in CORE_GROUPS:
        if verb in READ_VERBS or verb == "*":
            return "critical", "Can read Secret objects, which commonly contain credentials."
        if verb in CHANGE_VERBS:
            return "high", "Can create or replace credentials and configuration stored in Secrets."
    if (
        full == "serviceaccounts/token"
        and group in CORE_GROUPS
        and verb in {"create", "*"}
    ):
        return "critical", "Can mint a token for a ServiceAccount it can name."
    if full == "nodes/proxy" and group in CORE_GROUPS and verb in {"get", "create", "*"}:
        return "critical", "Can reach kubelet APIs through the API server."
    if (
        verb in {"bind", "escalate"}
        and _group_is(group, "rbac.authorization.k8s.io")
        and resource in {"roles", "clusterroles", "*"}
    ):
        return (
            "critical",
            f"Can use the special {verb} capability to bypass RBAC escalation safeguards.",
        )
    if verb == "impersonate" and group in CORE_GROUPS:
        if resource in {"users", "serviceaccounts", "*"}:
            return (
                "critical",
                "Can perform authorized requests using another user or ServiceAccount.",
            )
        if resource == "groups":
            return (
                "high",
                "Can add groups to an impersonated user when a matching "
                "user-impersonation grant is also held.",
            )
    if (
        verb == "impersonate"
        and _group_is(group, "authentication.k8s.io")
        and resource in {"uids", "userextras"}
    ):
        return (
            "medium",
            "Can add UID or extra fields only while a separately authorized user "
            "is impersonated.",
        )
    if verb.startswith("impersonate-on:"):
        delegated_verb = verb.rsplit(":", 1)[-1]
        delegated_key = PermissionKey(
            verb=delegated_verb,
            group=key.group,
            version=key.version,
            resource=key.resource,
            subresource=key.subresource,
            namespace=key.namespace,
            name=key.name,
        )
        delegated_severity, _ = classify_permission(delegated_key)
        severity = "high" if delegated_severity in {"critical", "high"} else "medium"
        return severity, (
            f"Constrained impersonation can perform {delegated_verb} on {full} when the matching "
            "impersonated-identity permission is also held."
        )
    if verb.startswith("impersonate:") and _group_is(group, "authentication.k8s.io"):
        mode = verb.split(":", 1)[1]
        if mode in {"user-info", "serviceaccount", "arbitrary-node"}:
            return (
                "high",
                f"Can select an identity for constrained {mode} impersonation when "
                "matching action grants are held.",
            )
        return "medium", f"Conditional constrained-impersonation identity capability {verb}."
    if (
        verb == "approve"
        and _group_is(group, "certificates.k8s.io")
        and resource in {"signers", "*"}
    ):
        return "high", "Can approve a signer request in a certificate-minting chain."
    if (
        verb in {"sign", "attest"}
        and _group_is(group, "certificates.k8s.io")
        and resource in {"signers", "*"}
    ):
        return (
            "medium",
            f"Conditional signer capability {verb}; a compatible controller and "
            "mutation chain are required.",
        )
    if resource == "certificatesigningrequests" and _group_is(group, "certificates.k8s.io"):
        if not subresource and verb in {"create", "*"}:
            return "high", "Can submit a CSR for a user, node, or workload identity."
        if subresource == "approval" and verb in {"update", "patch", "*"}:
            return "high", "Can approve a CSR when the matching Signer approval grant is also held."
        if subresource == "status" and verb in {"update", "patch", "*"}:
            return "medium", "Can change CSR status only in a compatible signer/controller chain."
    if (
        full in {"pods/exec", "pods/attach", "pods/portforward", "pods/proxy"}
        and group in CORE_GROUPS
        and verb in {"create", "get", "*"}
    ):
        return "high", f"Can access sensitive Pod subresource {full}."
    if full == "services/proxy" and group in CORE_GROUPS and verb in {"create", "get", "*"}:
        return "high", "Can reach a Service backend through the API-server proxy."
    if full == "pods/ephemeralcontainers" and group in CORE_GROUPS and verb in {
        "update",
        "patch",
        "*",
    }:
        return "high", "Can inject an ephemeral container into an existing Pod."
    if full == "pods/binding" and group in CORE_GROUPS and verb in {"create", "*"}:
        return "high", "Can assign an unscheduled Pod directly to a Node."
    if full == "pods/eviction" and group in CORE_GROUPS and verb in {"create", "*"}:
        return (
            "medium",
            "Can request Pod eviction; impact is normally availability or a "
            "second-step replacement.",
        )
    if resource == "bindings" and group in CORE_GROUPS and verb in {"create", "*"}:
        return "high", "Can submit a direct Pod-to-Node binding request."
    if (
        full in {"pods/status", "services/status"}
        and group in CORE_GROUPS
        and verb in {"update", "patch", "*"}
    ):
        return "high", f"Can redirect traffic by changing controller-observed state through {full}."
    if full == "nodes/status" and group in CORE_GROUPS and verb in {"update", "patch", "*"}:
        return (
            "medium",
            "Can change Node capacity or conditions; no portable privilege path is assumed.",
        )
    if resource in {
        "selfsubjectaccessreviews",
        "selfsubjectrulesreviews",
        "selfsubjectreviews",
    }:
        return "low", "Can ask the API server about its own identity or permissions."
    if resource in {"subjectaccessreviews", "localsubjectaccessreviews", "tokenreviews"} and verb in {
        "create",
        "*",
    }:
        return (
            "medium",
            "Can query authentication or authorization data for supplied subjects "
            "or tokens.",
        )
    if verb == "request-serviceaccounts-token-audience":
        return (
            "medium",
            "Can widen a kubelet TokenRequest audience in a conditional "
            "node-identity chain.",
        )
    if resource == "pods" and not subresource and group in CORE_GROUPS and verb in {
        "create",
        "update",
        "patch",
        "*",
    }:
        return (
            "high",
            "Can create a workload or change Pod labels used by Services and policies, subject to admission.",
        )
    if (
        _is_workload(group, resource)
        and resource != "pods"
        and not subresource
        and verb in CHANGE_VERBS
    ):
        return (
            "high",
            "Can create or change a workload controller template. Impact depends on ServiceAccounts, "
            "mounts, node settings, and admission controls.",
        )
    if (
        resource in RBAC_RESOURCES
        and _group_is(group, "rbac.authorization.k8s.io")
        and _is_write_verb(verb)
    ):
        return (
            "medium",
            "Can change RBAC objects, but bind/escalate safeguards prevent gaining "
            "permissions not already held.",
        )
    if (
        resource in {"validatingadmissionpolicies", "validatingadmissionpolicybindings"}
        and _group_is(group, "admissionregistration.k8s.io")
        and verb in {
            "update",
            "patch",
            "delete",
            "deletecollection",
            "*",
        }
    ):
        return "high", "Can weaken or remove an enforced ValidatingAdmissionPolicy or binding."
    if (
        resource in {"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"}
        and _group_is(group, "admissionregistration.k8s.io")
        and verb in CHANGE_VERBS
    ):
        return (
            "high",
            "Can activate or change native admission mutations that inject code "
            "into later workloads.",
        )
    if (
        resource in {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}
        and _group_is(group, "admissionregistration.k8s.io")
        and verb in CHANGE_VERBS | {"delete", "deletecollection"}
    ):
        return (
            "high",
            "Can register, redirect, weaken, or remove an admission webhook. A "
            "reachable attacker-controlled mutating webhook can inject code into "
            "later workloads; a validating webhook receives matching objects, "
            "including Secret data.",
        )
    if (
        resource in ADMISSION_RESOURCES
        and _group_is(group, "admissionregistration.k8s.io")
        and _is_write_verb(verb)
    ):
        return (
            "medium",
            "Can change admission configuration; elevate only after reproducing "
            "the enforced policy path.",
        )
    if resource == "namespaces" and group in CORE_GROUPS and verb in {
        "create",
        "update",
        "patch",
        "*",
    }:
        return "high", "Can choose or change namespace labels used by admission policy selectors."
    if verb == "use" and resource in {"podsecuritypolicies", "securitycontextconstraints", "*"}:
        return (
            "medium",
            f"Can use admission/security profile resource {resource}; profile impact "
            "must be validated on the platform.",
        )
    if (
        resource in POLICY_REPORT_RESOURCES
        or ("gatekeeper" in group and subresource == "status")
    ) and _is_write_verb(verb):
        return "medium", "Can change policy-engine report or status data, but not the enforced policy."
    if "constraints.gatekeeper.sh" in group and _is_write_verb(verb):
        return "medium", "Can change a Gatekeeper constraint; the live controller effect must be validated."
    if any(policy_engine in group for policy_engine in ("kyverno", "gatekeeper")):
        if _is_write_verb(verb) and any(
            word in resource for word in ("policy", "constraint", "assign", "exception", "config")
        ):
            return "medium", "Can change a third-party admission object; validate the live controller effect."
    if (
        resource == "clustertrustbundles"
        and _group_is(group, "certificates.k8s.io")
        and verb in {"update", "patch", "*"}
    ):
        return "high", "Can replace trust anchors projected into opted-in workloads."
    if full == "nodes/checkpoint" and group in CORE_GROUPS and verb in {"create", "*"}:
        return (
            "medium",
            "Can request a container checkpoint only when the kubelet, runtime, and "
            "node authorization path support it; no portable privilege path is assumed.",
        )
    if resource == "networkpolicies" and _group_is(group, "networking.k8s.io") and verb in {
        "create",
        "update",
        "patch",
        "delete",
        "deletecollection",
        "*",
    }:
        return "high", "Can add an allow policy or weaken an enforced workload network boundary."
    if resource in {"services", "endpoints"} and group in CORE_GROUPS and verb in {
        "create",
        "update",
        "patch",
        "*",
    }:
        return "high", "Can name-squat or redirect cluster application traffic."
    if (
        resource == "endpointslices"
        and _group_is(group, "discovery.k8s.io")
        and verb in {"create", "update", "patch", "*"}
    ):
        return "high", "Can create or redirect backends for a selectorless Service."
    if resource in STORAGE_CONTROL_RESOURCES and group in CORE_GROUPS and verb in {"create", "*"}:
        return (
            "high",
            "Can create a PersistentVolume exposing node-backed data to a later PVC and Pod.",
        )
    if resource == "nodes" and not subresource and group in CORE_GROUPS and verb in {
        "update",
        "patch",
        "*",
    }:
        return "high", "Can change Node labels or taints and influence workload placement."
    if resource == "configmaps" and group in CORE_GROUPS and verb in CHANGE_VERBS:
        return (
            "high",
            "Can create a missing configuration name or change configuration "
            "consumed by workloads.",
        )
    if full in {
        "pods/log",
        "nodes/log",
        "nodes/stats",
        "nodes/metrics",
        "nodes/configz",
        "nodes/pods",
    }:
        return "medium", f"Can read operational data through {full}."
    if resource in MEDIUM_READ_RESOURCES and verb in READ_VERBS:
        return "medium", "Can read objects that commonly reveal identities, topology, or attack inputs."
    if verb in READ_VERBS:
        return "low", "Read-only API permission."
    if _is_write_verb(verb):
        return "medium", "Can change this resource; impact is resource-specific."
    return "low", "Kubernetes API permission."
