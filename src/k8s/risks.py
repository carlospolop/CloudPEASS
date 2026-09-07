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

TRAFFIC_RESOURCES = {
    "services",
    "endpointslices",
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
        if verb in READ_VERBS or verb == "*":
            return "critical", "Can read every current and future API resource, including Secrets."
        if verb in CHANGE_VERBS:
            return "high", "Can change every current and future API resource allowed by this scope."
    if resource == "secrets":
        if verb in READ_VERBS or verb == "*":
            return "critical", "Can read Secret objects, which commonly contain credentials."
        if verb in CHANGE_VERBS:
            return "high", "Can create or replace credentials and configuration stored in Secrets."
    if full == "serviceaccounts/token" and verb in {"create", "*"}:
        return "critical", "Can mint a token for a ServiceAccount it can name."
    if full == "nodes/proxy" and verb in {"get", "create", "*"}:
        return "critical", "Can reach kubelet APIs through the API server."
    if verb in {"bind", "escalate"} and resource in {"roles", "clusterroles", "*"}:
        return "critical", f"Can use the special {verb} capability to bypass RBAC escalation safeguards."
    if verb == "impersonate" and resource in {
        "users",
        "groups",
        "serviceaccounts",
        "userextras",
        "uids",
        "*",
    }:
        return "critical", "Can perform authorized requests using another Kubernetes identity."
    if verb == "approve" and resource in {"signers", "*"}:
        return "high", "Can approve a signer request in a certificate-minting chain."
    if verb in {"sign", "attest"} and resource in {"signers", "*"}:
        return "medium", f"Conditional signer capability {verb}; a compatible controller and mutation chain are required."
    if resource == "certificatesigningrequests":
        if not subresource and verb in {"create", "*"}:
            return "high", "Can submit a CSR for a user, node, or workload identity."
        if subresource == "approval" and verb in {"update", "patch", "*"}:
            return "high", "Can approve a CSR when the matching Signer approval grant is also held."
        if subresource == "status" and verb in {"update", "patch", "*"}:
            return "medium", "Can change CSR status only in a compatible signer/controller chain."
    if full in {"pods/exec", "pods/attach", "pods/portforward", "pods/proxy"} and verb in {
        "create",
        "get",
        "*",
    }:
        return "high", f"Can access sensitive Pod subresource {full}."
    if full == "services/proxy" and verb in {"create", "get", "*"}:
        return "high", "Can reach a Service backend through the API-server proxy."
    if full == "pods/ephemeralcontainers" and verb in {"update", "patch", "*"}:
        return "high", "Can inject an ephemeral container into an existing Pod."
    if full == "pods/binding" and verb in {"create", "*"}:
        return "high", "Can assign an unscheduled Pod directly to a Node."
    if full == "pods/eviction" and verb in {"create", "*"}:
        return "medium", "Can request Pod eviction; impact is normally availability or a second-step replacement."
    if resource == "bindings" and verb in {"create", "*"}:
        return "high", "Can submit a direct Pod-to-Node binding request."
    if full in {"pods/status", "nodes/status", "services/status"} and verb in {
        "update",
        "patch",
        "*",
    }:
        return "medium", f"Can change controller-observed state through {full}; no portable privilege path is assumed."
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
        return "medium", "Can query authentication or authorization data for supplied subjects or tokens."
    if verb == "request-serviceaccounts-token-audience":
        return "medium", "Can widen a kubelet TokenRequest audience in a conditional node-identity chain."
    if resource == "pods" and not subresource and verb in {"create", "*"}:
        return (
            "high",
            "Can create a workload and select its ServiceAccount, mounts, and security context subject to admission.",
        )
    if resource in (WORKLOADS - {"pods"}) and verb in CHANGE_VERBS:
        return (
            "high",
            "Can create or change a workload controller template. Impact depends on ServiceAccounts, "
            "mounts, node settings, and admission controls.",
        )
    if resource in RBAC_RESOURCES and verb in CHANGE_VERBS:
        return "high", "Can change RBAC objects; bind/escalate safeguards and existing grants decide impact."
    if resource == "validatingadmissionpolicybindings" and verb in {
        "update",
        "patch",
        "delete",
        "deletecollection",
        "*",
    }:
        return "high", "Can weaken or remove an enforced ValidatingAdmissionPolicy binding."
    if resource in ADMISSION_RESOURCES and _is_write_verb(verb):
        return "medium", "Can change admission configuration; elevate only after reproducing the enforced policy path."
    if resource == "namespaces" and verb in {"create", "update", "patch", "*"}:
        return "high", "Can choose or change namespace labels used by admission policy selectors."
    if verb == "use" and resource in {"podsecuritypolicies", "securitycontextconstraints", "*"}:
        return "medium", f"Can use admission/security profile resource {resource}; profile impact must be validated on the platform."
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
    if resource == "clustertrustbundles" and verb in {"update", "patch", "*"}:
        return "high", "Can replace trust anchors projected into opted-in workloads."
    if full == "nodes/checkpoint" and verb in {"create", "*"}:
        return (
            "medium",
            "Can request a container checkpoint only when the kubelet, runtime, and "
            "node authorization path support it; no portable privilege path is assumed.",
        )
    if resource == "networkpolicies" and verb in {
        "update",
        "patch",
        "delete",
        "deletecollection",
        "*",
    }:
        return "high", "Can weaken or redirect an enforced workload network boundary."
    if resource in TRAFFIC_RESOURCES and verb in {"update", "patch", "*"}:
        return "high", "Can redirect, intercept, or expose cluster application traffic."
    if resource in STORAGE_CONTROL_RESOURCES and verb in {"create", "*"}:
        return "high", "Can create a PersistentVolume exposing node-backed data to a later PVC and Pod."
    if resource == "nodes" and not subresource and verb in {"update", "patch", "*"}:
        return "high", "Can change Node labels or taints and influence workload placement."
    if resource == "configmaps" and verb in {"update", "patch", "*"}:
        return "high", "Can change configuration consumed by workloads or cluster components."
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
