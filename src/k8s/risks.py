"""Plain-language Kubernetes permission risk classification."""

from __future__ import annotations

from .models import PermissionKey


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
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*"}


def classify_permission(key: PermissionKey) -> tuple[str, str]:
    verb = key.verb.lower()
    resource = key.resource.lower()
    subresource = key.subresource.lower()
    full = f"{resource}/{subresource}" if subresource else resource

    if key.non_resource_url:
        path = key.non_resource_url
        if path in {"/api", "/api/*", "/apis", "/apis/*", "/version", "/openapi/*"}:
            return "low", "Basic API discovery access."
        if path.startswith(("/debug", "/logs")) or "*" in path:
            return "high", f"Can access sensitive API-server path {path}."
        return "low", f"Can access API-server path {path}."
    if verb == "*" and resource == "*":
        return "critical", "Has wildcard Kubernetes API access."
    if resource == "secrets" and verb in {"get", "list", "watch", "*"}:
        return "critical", "Can read Secret objects, which commonly contain credentials."
    if full == "serviceaccounts/token" and verb in {"create", "*"}:
        return "critical", "Can mint a token for a ServiceAccount it can name."
    if full == "nodes/proxy" and verb in {"get", "create", "*"}:
        return "critical", "Can reach kubelet APIs through the API server."
    if verb in {"bind", "escalate"}:
        return "critical", f"Can use the special {verb} authorization capability."
    if verb.startswith("impersonate"):
        return "critical", "Can perform requests using another Kubernetes identity."
    if verb in {"approve", "sign", "attest"}:
        return "high", f"Can use the special certificate or trust verb {verb}."
    if full in {
        "pods/exec",
        "pods/attach",
        "pods/ephemeralcontainers",
        "pods/portforward",
        "pods/proxy",
    }:
        return "high", f"Can access sensitive Pod subresource {full}."
    if resource in {
        "selfsubjectaccessreviews",
        "selfsubjectrulesreviews",
        "selfsubjectreviews",
    }:
        return "low", "Can ask the API server about its own identity or permissions."
    if resource in WORKLOADS and verb in WRITE_VERBS:
        return (
            "high",
            "Can create or change a workload. Impact depends on ServiceAccounts, "
            "mounts, node settings, and admission controls.",
        )
    if resource in {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}:
        if verb in WRITE_VERBS:
            return "high", "Can change RBAC objects; escalation checks may apply."
    admission_resources = {
        "mutatingwebhookconfigurations",
        "validatingwebhookconfigurations",
        "mutatingadmissionpolicies",
        "mutatingadmissionpolicybindings",
        "validatingadmissionpolicies",
        "validatingadmissionpolicybindings",
    }
    if resource in admission_resources and verb in WRITE_VERBS:
        return "high", "Can change admission configuration or policy."
    if resource == "namespaces" and verb in {"patch", "update", "*"}:
        return "high", "Can change namespace labels used by security controls."
    if resource == "namespaces" and verb == "create":
        return "high", "Can create a namespace and choose its security labels."
    if verb == "use" and resource in {"podsecuritypolicies", "securitycontextconstraints"}:
        return "high", f"Can use admission/security profile resource {resource}."
    if any(name in key.group.lower() for name in ("kyverno", "gatekeeper")):
        if verb in WRITE_VERBS and any(
            word in resource for word in ("policy", "constraint", "assign", "exception")
        ):
            return "high", "Can change a third-party admission policy object."
    if resource == "persistentvolumes" and verb in {"create", "patch", "update", "*"}:
        return "high", "Can influence cluster storage, including hostPath paths."
    if full in {"pods/log", "nodes/log", "nodes/stats", "nodes/metrics"}:
        return "medium", f"Can read operational data through {full}."
    if verb in {"get", "list", "watch"}:
        return "low", "Read-only API permission."
    if verb in WRITE_VERBS:
        return "medium", "Can change this resource; impact is resource-specific."
    return "low", "Kubernetes API permission."
