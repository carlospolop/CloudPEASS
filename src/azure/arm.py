"""Read-only Azure Resource Manager permission and resource enumeration."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Iterable, List, Optional, Tuple
import jwt
from src.CloudPEASS.http import ReadOnlyHttpClient


ARM_HOST = "https://management.azure.com"
ARM_ENDPOINTS = {
    "https://management.azure.com": ARM_HOST,
    "https://management.core.windows.net": ARM_HOST,
    "https://management.usgovcloudapi.net": "https://management.usgovcloudapi.net",
    "https://management.core.usgovcloudapi.net": "https://management.usgovcloudapi.net",
    "https://management.chinacloudapi.cn": "https://management.chinacloudapi.cn",
    "https://management.core.chinacloudapi.cn": "https://management.chinacloudapi.cn",
    "https://management.microsoftazure.de": "https://management.microsoftazure.de",
    "https://management.core.cloudapi.de": "https://management.microsoftazure.de",
}


@dataclass
class PermissionResult:
    allowed: List[str] = field(default_factory=list)
    excluded: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.status_code == 200


class AzureARMEnumerator:
    """Collect effective ARM permissions without making Azure changes."""

    def __init__(self, token: str, *, max_retries: int = 4, http=None):
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"}
        try:
            audience = jwt.decode(
                token, options={"verify_signature": False, "verify_aud": False}
            ).get("aud", "")
        except Exception:
            audience = ""
        self.endpoint = ARM_ENDPOINTS.get(str(audience).rstrip("/").lower(), ARM_HOST)
        self.http = http or ReadOnlyHttpClient(
            allowed_hosts={self.endpoint.split("//", 1)[-1]}, max_retries=max_retries
        )
        self._role_cache: Dict[str, Optional[dict]] = {}
        self._role_lock = Lock()

    @staticmethod
    def error_text(response) -> str:
        try:
            body = response.json()
            error = body.get("error", body)
            code = error.get("code", "UnknownError")
            message = error.get("message", "")
            return f"{code}: {message}"[:500]
        except (ValueError, AttributeError):
            return (getattr(response, "text", "") or "Unknown API error")[:500]

    def _list(self, url: str, *, params=None) -> Tuple[List[dict], int, Optional[str]]:
        values = []
        status = 0
        try:
            for response in self.http.iter_pages(url, headers=self.headers, params=params):
                status = response.status_code
                if status < 200 or status >= 300:
                    return values, status, self.error_text(response)
                try:
                    data = response.json()
                except ValueError:
                    return values, status, "Azure returned a non-JSON response"
                values.extend(data.get("value", []))
        except Exception as exc:
            return values, status, str(exc)[:500]
        return values, status or 200, None

    def list_subscriptions(self) -> Tuple[List[dict], int, Optional[str]]:
        return self._list(
            f"{self.endpoint}/subscriptions", params={"api-version": "2022-12-01"}
        )

    def list_resource_groups(self, subscription_id: str):
        return self._list(
            f"{self.endpoint}/subscriptions/{subscription_id}/resourcegroups",
            params={"api-version": "2021-04-01"},
        )

    def list_resources(self, subscription_id: str):
        return self._list(
            f"{self.endpoint}/subscriptions/{subscription_id}/resources",
            params={"api-version": "2021-04-01"},
        )

    def list_management_groups(self):
        return self._list(
            f"{self.endpoint}/providers/Microsoft.Management/managementGroups",
            params={"api-version": "2021-04-01"},
        )

    @staticmethod
    def permissions_from_blocks(blocks: Iterable[dict]) -> Tuple[List[str], List[str]]:
        allowed = set()
        excluded = set()
        for block in blocks:
            allowed.update(str(value) for value in (block.get("actions") or []) if value)
            allowed.update(str(value) for value in (block.get("dataActions") or []) if value)
            excluded.update(str(value) for value in (block.get("notActions") or []) if value)
            excluded.update(
                str(value) for value in (block.get("notDataActions") or []) if value
            )
        return sorted(allowed, key=str.lower), sorted(excluded, key=str.lower)

    def get_effective_permissions(self, scope: str) -> PermissionResult:
        scope = "/" + scope.strip("/")
        blocks, status, error = self._list(
            f"{self.endpoint}{scope}/providers/Microsoft.Authorization/permissions",
            params={"api-version": "2022-04-01"},
        )
        allowed, excluded = self.permissions_from_blocks(blocks)
        return PermissionResult(allowed, excluded, status, error)

    def get_role_definition(self, role_definition_id: str) -> Optional[dict]:
        if not role_definition_id:
            return None
        with self._role_lock:
            if role_definition_id in self._role_cache:
                return self._role_cache[role_definition_id]

        url = role_definition_id
        if not url.lower().startswith("https://"):
            url = f"{self.endpoint}/" + role_definition_id.lstrip("/")
        try:
            response = self.http.get(
                url, headers=self.headers, params={"api-version": "2022-04-01"}
            )
            role = response.json() if response.status_code == 200 else None
        except Exception:
            role = None
        with self._role_lock:
            self._role_cache[role_definition_id] = role
        return role

    def permissions_for_role(self, role_definition_id: str) -> PermissionResult:
        role = self.get_role_definition(role_definition_id)
        if not role:
            return PermissionResult(error="Role definition could not be read")
        allowed, excluded = self.permissions_from_blocks(
            role.get("properties", {}).get("permissions", [])
        )
        return PermissionResult(allowed, excluded, 200, None)

    def list_assignments_for_principal(self, scope: str, principal_id: str):
        """Use the IAM-readable fallback, including transitive group assignments."""

        scope = "/" + scope.strip("/")
        return self._list(
            f"{self.endpoint}{scope}/providers/Microsoft.Authorization/roleAssignments",
            params={
                "api-version": "2022-04-01",
                "$filter": f"assignedTo('{principal_id}')",
            },
        )

    def list_eligible_assignments(self, scope: str):
        """List PIM-eligible ARM roles for the current user."""

        scope = "/" + scope.strip("/")
        return self._list(
            f"{self.endpoint}{scope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances",
            params={"api-version": "2020-10-01", "$filter": "asTarget()"},
        )


def scope_kind(scope: str) -> str:
    parts = [part for part in scope.strip("/").split("/") if part]
    lowered = [part.lower() for part in parts]
    if lowered[:2] == ["providers", "microsoft.management"]:
        return "management_group"
    if len(parts) == 2 and lowered[0] == "subscriptions":
        return "subscription"
    if "resourcegroups" in lowered and "providers" not in lowered:
        return "resource_group"
    if "providers" in lowered:
        return "resource"
    return "azure_scope"


def scope_name(scope: str) -> str:
    parts = [part for part in scope.strip("/").split("/") if part]
    return parts[-1] if parts else scope
