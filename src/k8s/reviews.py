"""Identity and authorization review helpers."""

from __future__ import annotations

import base64
import json
from typing import Any

from .client import APIError, K8sClient
from .models import PermissionFinding, PermissionKey
from .risks import classify_permission


SELF_REVIEW_PATH = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
ACCESS_REVIEW_PATH = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
RULES_REVIEW_PATH = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"


def decode_jwt_without_verification(token: str | None) -> dict[str, Any]:
    """Decode selected JWT claims without trusting them as live identity."""
    if not token or token.count(".") != 2:
        return {}
    try:
        payload = token.split(".", 2)[1]
        payload += "=" * (-len(payload) % 4)
        value = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    safe_names = {"iss", "sub", "aud", "exp", "nbf", "iat"}
    result = {name: value[name] for name in safe_names if name in value}
    kubernetes_claims = value.get("kubernetes.io")
    if isinstance(kubernetes_claims, dict):
        result["kubernetes.io"] = kubernetes_claims
    return result


def get_identity(
    client: K8sClient, explicit_token: str | None = None
) -> tuple[dict[str, Any], str, list[str]]:
    """Return live identity, evidence method, and non-fatal warnings."""
    warnings: list[str] = []
    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "SelfSubjectReview",
    }
    try:
        response = client.post_review(SELF_REVIEW_PATH, body)
        user_info = ((response.get("status") or {}).get("userInfo") or {})
        if user_info:
            return user_info, "SelfSubjectReview", warnings
    except APIError as exc:
        warnings.append(f"SelfSubjectReview unavailable: {exc}")

    context = client.context_info()
    claims = decode_jwt_without_verification(explicit_token)
    identity = {
        "username": claims.get("sub") or "unknown",
        "groups": [],
        "uid": "",
        "extra": {},
        "unverifiedJwtClaims": claims,
        "localContext": context,
    }
    warnings.append(
        "The API server did not reveal the live identity. Local context and JWT "
        "claims are unverified fallbacks."
    )
    return identity, "local-fallback", warnings


def self_subject_access_review(
    client: K8sClient, key: PermissionKey
) -> PermissionFinding:
    if key.non_resource_url:
        spec: dict[str, Any] = {
            "nonResourceAttributes": {
                "verb": key.verb,
                "path": key.non_resource_url,
            }
        }
    else:
        attributes: dict[str, Any] = {
            "verb": key.verb,
            "group": key.group,
            "version": key.version,
            "resource": key.resource,
            "subresource": key.subresource,
            "namespace": key.namespace,
            "name": key.name,
        }
        if key.field_selector:
            attributes["fieldSelector"] = {"rawSelector": key.field_selector}
        if key.label_selector:
            attributes["labelSelector"] = {"rawSelector": key.label_selector}
        spec = {"resourceAttributes": attributes}

    body = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": spec,
    }
    try:
        response = client.post_review(ACCESS_REVIEW_PATH, body)
        status = response.get("status") or {}
    except APIError as exc:
        severity, explanation = classify_permission(key)
        return PermissionFinding(
            key=key,
            allowed=False,
            reason=str(exc),
            evaluation_error=str(exc),
            confidence="unknown",
            severity=severity,
            explanation=explanation,
        )
    severity, explanation = classify_permission(key)
    return PermissionFinding(
        key=key,
        allowed=bool(status.get("allowed")),
        denied=bool(status.get("denied")),
        reason=str(status.get("reason") or ""),
        evaluation_error=str(status.get("evaluationError") or ""),
        confidence="confirmed",
        severity=severity,
        explanation=explanation,
    )


def self_subject_rules_review(
    client: K8sClient, namespace: str
) -> tuple[dict[str, Any], str]:
    body = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "spec": {"namespace": namespace},
    }
    try:
        response = client.post_review(RULES_REVIEW_PATH, body)
    except APIError as exc:
        return {}, str(exc)
    return response.get("status") or {}, ""


def findings_from_rules(
    status: dict[str, Any], namespace: str
) -> list[PermissionFinding]:
    """Convert a rules summary to readable findings without overclaiming."""
    findings: list[PermissionFinding] = []
    confidence = "incomplete" if status.get("incomplete") else "summarized"
    for rule in status.get("resourceRules") or []:
        names = [str(name) for name in (rule.get("resourceNames") or [])]
        for group in rule.get("apiGroups") or [""]:
            for resource_name in rule.get("resources") or ["*"]:
                resource, _, subresource = str(resource_name).partition("/")
                for verb in rule.get("verbs") or []:
                    for name in names or [""]:
                        is_collection = str(verb) in {"list", "watch"}
                        key = PermissionKey(
                            verb=str(verb),
                            group=str(group),
                            resource=resource,
                            subresource=subresource,
                            namespace=namespace,
                            name="" if is_collection else name,
                            field_selector=(
                                f"metadata.name={name}" if name and is_collection else ""
                            ),
                        )
                        severity, explanation = classify_permission(key)
                        findings.append(
                            PermissionFinding(
                                key=key,
                                allowed=True,
                                evidence="SelfSubjectRulesReview",
                                confidence=confidence,
                                severity=severity,
                                explanation=explanation,
                                resource_names=names,
                            )
                        )
    for rule in status.get("nonResourceRules") or []:
        for path in rule.get("nonResourceURLs") or []:
            for verb in rule.get("verbs") or []:
                key = PermissionKey(verb=str(verb), non_resource_url=str(path))
                severity, explanation = classify_permission(key)
                findings.append(
                    PermissionFinding(
                        key=key,
                        allowed=True,
                        evidence="SelfSubjectRulesReview",
                        confidence=confidence,
                        severity=severity,
                        explanation=explanation,
                    )
                )
    return findings
