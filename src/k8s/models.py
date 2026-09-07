"""Structured models for Kubernetes permission enumeration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class APIResource:
    group: str
    version: str
    resource: str
    subresource: str = ""
    namespaced: bool = False
    verbs: tuple[str, ...] = ()
    kind: str = ""

    @property
    def full_resource(self) -> str:
        if self.subresource:
            return f"{self.resource}/{self.subresource}"
        return self.resource

    @property
    def api_name(self) -> str:
        return f"{self.full_resource}.{self.group}" if self.group else self.full_resource


@dataclass(frozen=True)
class PermissionKey:
    verb: str
    group: str = ""
    version: str = ""
    resource: str = ""
    subresource: str = ""
    namespace: str = ""
    name: str = ""
    non_resource_url: str = ""
    field_selector: str = ""
    label_selector: str = ""

    @property
    def is_non_resource(self) -> bool:
        return bool(self.non_resource_url)

    @property
    def full_resource(self) -> str:
        if self.subresource:
            return f"{self.resource}/{self.subresource}"
        return self.resource

    def human(self) -> str:
        if self.non_resource_url:
            return f"{self.verb} {self.non_resource_url}"
        target = self.full_resource
        if self.group:
            target += f".{self.group}"
        if self.name:
            target += f"/{self.name}"
        scope = f" in namespace {self.namespace}" if self.namespace else " cluster-wide"
        selectors = []
        if self.field_selector:
            selectors.append(f"fields={self.field_selector}")
        if self.label_selector:
            selectors.append(f"labels={self.label_selector}")
        suffix = f" ({', '.join(selectors)})" if selectors else ""
        return f"{self.verb} {target}{scope}{suffix}"


@dataclass
class PermissionFinding:
    key: PermissionKey
    allowed: bool
    denied: bool = False
    reason: str = ""
    evaluation_error: str = ""
    evidence: str = "SelfSubjectAccessReview"
    confidence: str = "confirmed"
    severity: str = "low"
    explanation: str = ""
    admission: str = "not-applicable"
    resource_names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["description"] = self.key.human()
        return result


@dataclass
class Coverage:
    identity_method: str = "unknown"
    discovery_complete: bool = False
    namespace_sources: dict[str, list[str]] = field(default_factory=dict)
    hidden_namespaces_possible: bool = True
    rules_reviews_complete: bool = True
    rules_review_errors: list[str] = field(default_factory=list)
    exact_checks: int = 0
    brute_force_run: bool = False
    brute_force_skipped_reason: str = ""
    readable_inventories: list[str] = field(default_factory=list)
    unavailable_inventories: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
