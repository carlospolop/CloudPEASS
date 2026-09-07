"""Resilient, read-only Microsoft Entra ID permission enumeration."""

from __future__ import annotations

from threading import Lock
from typing import Dict, Optional

import jwt
from colorama import Fore, Style, init

from src.CloudPEASS.cloudpeass import CloudResource
from src.CloudPEASS.http import ReadOnlyHttpClient


init(autoreset=True)
GRAPH = "https://graph.microsoft.com"
GRAPH_ENDPOINTS = {
    "https://graph.microsoft.com": GRAPH,
    "https://graph.microsoft.us": "https://graph.microsoft.us",
    "https://dod-graph.microsoft.us": "https://dod-graph.microsoft.us",
    "https://microsoftgraph.chinacloudapi.cn": "https://microsoftgraph.chinacloudapi.cn",
}


class EntraIDPEASS:
    def __init__(self, token, num_threads, http=None):
        self.user_id = None
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "ConsistencyLevel": "eventual",
        }
        self.num_threads = max(1, int(num_threads))
        self.decoded_token = {}
        self._role_cache: Dict[str, Optional[dict]] = {}
        self._sp_cache: Dict[str, Optional[dict]] = {}
        self._cache_lock = Lock()
        try:
            if token:
                self.decoded_token = jwt.decode(
                    token, options={"verify_signature": False, "verify_aud": False}
                )
        except Exception:
            pass
        audience = str(self.decoded_token.get("aud") or "").rstrip("/").lower()
        self.graph = GRAPH_ENDPOINTS.get(audience)
        if not self.graph and audience == "00000003-0000-0000-c000-000000000000":
            issuer = str(self.decoded_token.get("iss") or "").lower()
            if "microsoftonline.us" in issuer:
                self.graph = "https://graph.microsoft.us"
            elif "microsoftonline.cn" in issuer:
                self.graph = "https://microsoftgraph.chinacloudapi.cn"
        self.graph = self.graph or GRAPH
        self.http = http or ReadOnlyHttpClient(
            allowed_hosts={self.graph.split("//", 1)[-1]}, max_retries=4
        )

    @property
    def is_application(self):
        claims = self.decoded_token
        return claims.get("idtyp") == "app" or (
            bool(claims.get("appid") or claims.get("azp")) and not claims.get("scp")
        )

    @staticmethod
    def _error_text(response):
        try:
            body = response.json()
            error = body.get("error", body)
            code = error.get("code") or error.get("errorCode") or "UnknownError"
            message = error.get("message") or error.get("error_description") or ""
            return f"{code}: {message}"[:500]
        except (ValueError, AttributeError):
            return (getattr(response, "text", "") or "Unknown Graph error")[:500]

    def _claim_values(self, name):
        value = self.decoded_token.get(name)
        if not value:
            return []
        if isinstance(value, str):
            return value.split() if name == "scp" else [value]
        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value if item]
        return [str(value)]

    def _get(self, url, params=None):
        return self.http.get(url, headers=self.headers, params=params)

    def get_all_pages(self, url, cont=0, quiet=False):
        results = []
        try:
            for response in self.http.iter_pages(url, headers=self.headers):
                if response.status_code != 200:
                    error = self._error_text(response)
                    if "request is only valid with delegated authentication" in error.lower():
                        return None
                    if not quiet:
                        print(
                            f"{Fore.YELLOW}[!] Graph read unavailable ({response.status_code}): "
                            f"{error}{Style.RESET_ALL}"
                        )
                    return results
                try:
                    results.extend(response.json().get("value", []))
                except ValueError:
                    if not quiet:
                        print(f"{Fore.YELLOW}[!] Graph returned a non-JSON response.{Style.RESET_ALL}")
                    return results
        except Exception as exc:
            if not quiet:
                print(f"{Fore.YELLOW}[!] Graph request failed: {str(exc)[:300]}{Style.RESET_ALL}")
        return results

    def get_my_user_id(self):
        if self.user_id:
            return self.user_id
        if self.decoded_token.get("oid") and not self.is_application:
            self.user_id = self.decoded_token["oid"]
            return self.user_id
        response = self._get(f"{self.graph}/v1.0/me?$select=id")
        if response.status_code != 200:
            raise RuntimeError(f"Failed to get user ID: {self._error_text(response)}")
        self.user_id = response.json().get("id")
        return self.user_id

    @staticmethod
    def _permissions_from_role(role):
        permissions = set()
        for block in (role or {}).get("rolePermissions", []):
            permissions.update(block.get("allowedResourceActions") or [])
        return sorted(permissions, key=str.lower)

    def get_role_definition(self, role_definition_id):
        if not role_definition_id:
            return None
        with self._cache_lock:
            if role_definition_id in self._role_cache:
                return self._role_cache[role_definition_id]
        try:
            response = self._get(
                f"{self.graph}/v1.0/roleManagement/directory/roleDefinitions/{role_definition_id}"
            )
            role = response.json() if response.status_code == 200 else None
            if role is None:
                escaped = str(role_definition_id).replace("'", "''")
                matches = self.get_all_pages(
                    f"{self.graph}/v1.0/roleManagement/directory/roleDefinitions"
                    f"?$filter=templateId eq '{escaped}'",
                    quiet=True,
                )
                role = matches[0] if matches else None
        except Exception:
            role = None
        with self._cache_lock:
            self._role_cache[role_definition_id] = role
        return role

    def get_role_name(self, role_definition_id):
        role = self.get_role_definition(role_definition_id)
        return (role or {}).get("displayName") or role_definition_id

    def get_granular_permissions(self, role_id):
        role = self.get_role_definition(role_id)
        return self._permissions_from_role(role) if role else []

    def _role_resource(self, item, assignment_type="Assigned"):
        role_definition = item.get("roleDefinition") or {}
        role_id = item.get("roleDefinitionId") or item.get("roleTemplateId") or item.get("id")
        if not role_definition:
            role_definition = self.get_role_definition(role_id) or {}
        permissions = self._permissions_from_role(role_definition)
        if not permissions:
            permissions = self.get_granular_permissions(role_id)
        if not permissions and role_id:
            permissions = [f"entra.directoryRole/{role_id}"]
        scope = item.get("directoryScopeId") or "/"
        return CloudResource(
            resource_id=f"#microsoft.graph:roleDefinitionId:{role_id}:{scope}:{assignment_type.lower()}",
            name=role_definition.get("displayName") or item.get("displayName") or role_id,
            resource_type=scope,
            permissions=permissions,
            deny_perms=[],
            assignmentType=assignment_type,
        )

    def get_token_permissions(self):
        """Zero-directory-permission fallback based on signed token claims."""
        resources = []
        scopes = self._claim_values("scp")
        roles = self._claim_values("roles")
        if scopes or roles:
            resources.append(
                CloudResource(
                    resource_id="#microsoft.graph:token-claims",
                    name="Permissions proven by Graph token claims",
                    resource_type="token-claims",
                    permissions=sorted(set(scopes + roles), key=str.lower),
                    deny_perms=[],
                    assignmentType="TokenClaim",
                )
            )
        for role_id in self._claim_values("wids"):
            resources.append(self._role_resource({"roleDefinitionId": role_id}, "TokenClaim"))
        return resources

    def get_entraid_memberships(self):
        if self.is_application:
            return None
        url = f"{self.graph}/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=id,displayName,roleTemplateId"
        roles = self.get_all_pages(url)
        return [self._role_resource(role, "Transitive") for role in (roles or [])]

    def get_assigned_permissions(self):
        if self.is_application:
            return []
        try:
            principal_id = self.get_my_user_id()
        except Exception as exc:
            print(f"{Fore.YELLOW}[!] Cannot identify user for Entra role fallback: {exc}")
            return []
        url = (
            f"{self.graph}/beta/roleManagement/directory/transitiveRoleAssignments"
            f"?$count=true&$filter=principalId eq '{principal_id}'"
        )
        assignments = self.get_all_pages(url)
        return [self._role_resource(item, "Transitive") for item in (assignments or [])]

    def _get_service_principal(self, identifier):
        if not identifier:
            return None
        with self._cache_lock:
            if identifier in self._sp_cache:
                return self._sp_cache[identifier]
        response = self._get(f"{self.graph}/v1.0/servicePrincipals/{identifier}")
        service_principal = response.json() if response.status_code == 200 else None
        if service_principal is None:
            escaped = str(identifier).replace("'", "''")
            response = self._get(f"{self.graph}/v1.0/servicePrincipals(appId='{escaped}')")
            service_principal = response.json() if response.status_code == 200 else None
        with self._cache_lock:
            self._sp_cache[identifier] = service_principal
        return service_principal

    def _get_app_role_value(self, resource_id, app_role_id):
        service_principal = self._get_service_principal(resource_id)
        for role in (service_principal or {}).get("appRoles", []):
            if str(role.get("id")) == str(app_role_id):
                return role.get("value") or role.get("displayName")
        return None

    def _app_role_resources(self, assignments):
        resources = []
        for assignment in assignments or []:
            value = self._get_app_role_value(
                assignment.get("resourceId"), assignment.get("appRoleId")
            )
            if not value:
                continue
            resources.append(
                CloudResource(
                    resource_id=f"#microsoft.graph:appRoleAssignment:{assignment.get('id') or assignment.get('appRoleId')}",
                    name=assignment.get("resourceDisplayName") or value,
                    resource_type="appRoleAssignment",
                    permissions=[value],
                    deny_perms=[],
                    assignmentType="Assigned",
                )
            )
        return resources

    def get_my_app_role_assignments(self):
        if self.is_application:
            return []
        assignments = self.get_all_pages(f"{self.graph}/v1.0/me/appRoleAssignments")
        return self._app_role_resources(assignments)

    def get_eligible_roles(self):
        if self.is_application:
            return []
        try:
            principal_id = self.get_my_user_id()
        except Exception:
            return []
        url = (
            f"{self.graph}/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
            f"?$filter=principalId eq '{principal_id}'&$expand=roleDefinition"
        )
        roles = self.get_all_pages(url)
        return [self._role_resource(role, "Eligible") for role in (roles or [])]

    def _owned_objects(self, owner_path):
        objects = self.get_all_pages(
            f"{self.graph}/v1.0/{owner_path}/ownedObjects?$select=id,displayName,appDisplayName"
        )
        resources = []
        for item in objects or []:
            object_id = item.get("id")
            object_type = item.get("@odata.type", "directoryObject")
            resources.append(
                CloudResource(
                    resource_id=f"#microsoft.graph:ownedObject:{object_id}",
                    name=item.get("displayName") or item.get("appDisplayName") or object_id,
                    resource_type=object_type,
                    permissions=[f"Owner of {object_type}"],
                    deny_perms=[],
                    assignmentType="Owner",
                )
            )
        return resources

    def get_entraid_owns(self):
        return [] if self.is_application else self._owned_objects("me")

    def get_api_permissions(self):
        # Requested application permissions are not necessarily granted. Claims are.
        return self.get_token_permissions()

    def get_sp_principal_id(self):
        return self.decoded_token.get("oid") if self.is_application else None

    def check_sp_has_entraid_permissions(self, sp_id):
        if not sp_id:
            return False
        if self.decoded_token.get("roles") or self.decoded_token.get("wids"):
            return True
        checks = (
            f"{self.graph}/v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{sp_id}'&$top=1",
            f"{self.graph}/v1.0/servicePrincipals/{sp_id}/transitiveMemberOf?$top=1",
            f"{self.graph}/v1.0/servicePrincipals/{sp_id}/appRoleAssignments?$top=1",
        )
        return any(self.get_all_pages(url, quiet=True) for url in checks)

    def get_sp_directory_role_assignments(self, sp_id):
        resources = []
        endpoints = (
            (f"{self.graph}/v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{sp_id}'&$expand=roleDefinition", "Assigned"),
            (f"{self.graph}/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '{sp_id}'&$expand=roleDefinition", "Assigned"),
            (f"{self.graph}/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&$filter=principalId eq '{sp_id}'", "Transitive"),
        )
        for url, assignment_type in endpoints:
            resources.extend(
                self._role_resource(item, assignment_type)
                for item in (self.get_all_pages(url) or [])
            )
        return resources

    def get_sp_group_memberships(self, sp_id):
        url = (
            f"{self.graph}/v1.0/servicePrincipals/{sp_id}/transitiveMemberOf/"
            "microsoft.graph.directoryRole?$select=id,displayName,roleTemplateId"
        )
        return [self._role_resource(item, "Transitive") for item in (self.get_all_pages(url) or [])]

    def get_sp_app_role_assignments(self, sp_id):
        assignments = self.get_all_pages(f"{self.graph}/v1.0/servicePrincipals/{sp_id}/appRoleAssignments")
        return self._app_role_resources(assignments)

    def get_sp_eligible_roles(self, sp_id):
        url = (
            f"{self.graph}/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
            f"?$filter=principalId eq '{sp_id}'&$expand=roleDefinition"
        )
        return [self._role_resource(item, "Eligible") for item in (self.get_all_pages(url) or [])]

    def get_sp_owned_objects(self, sp_id):
        return self._owned_objects(f"servicePrincipals/{sp_id}")
