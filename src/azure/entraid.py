import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init, Back
import time

init(autoreset=True)

class EntraIDPEASS():
    def __init__(self, token, num_threads):
        self.user_id = None
        self.headers = {
            "Authorization": f"Bearer {token}",
            "ConsistencyLevel": "eventual"
        }
        self.num_threads = num_threads

    def get_my_user_id(self):

        if self.user_id:
            return self.user_id

        resp = requests.get("https://graph.microsoft.com/v1.0/me?$select=id", headers=self.headers)
        if resp.status_code != 200:
            raise Exception(f"Failed to get user ID: {resp.text}")
        
        self.user_id = resp.json().get("id")
        return self.user_id

    def get_role_name(self, role_definition_id):
        url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{role_definition_id}"
        resp = requests.get(url, headers=self.headers)

        if resp.status_code != 200:
            raise Exception(f"Failed retrieving role definition: {resp.text}")

        role_info = resp.json()
        return role_info.get("displayName", role_definition_id)

    # Helper function to handle paginated Graph results
    def get_all_pages(self, url, cont=0):
        results = []
        while url:
            resp = requests.get(url, headers=self.headers)
            if resp.status_code != 200:
                if "/me request is only valid with delegated authentication" in resp.text:
                    print(f"{Fore.RED}This is a token from a MI or a SP, it cannot access it's permissions in Entra ID (and it probably doesn't have any). Skipping.{Style.RESET_ALL}")
                    return None
                else:
                    print(f"{Fore.RED}Graph API call failed: {url} -> {resp.status_code} {resp.text}.{Style.RESET_ALL}")
                    if resp.status_code == 403: # If 403, not enough scopes, just continue
                        return results
                
                    if cont < 3:
                        time.sleep(2)
                        print(f"{Fore.YELLOW}Retrying...{Style.RESET_ALL}")
                        cont += 1
                        continue
                
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")  # if more pages, Graph provides nextLink
        return results

    def get_granular_permissions(self, role_id):
        # Retrieve granular permissions assigned to a directory role from role definitions
        url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{role_id}"
        resp = requests.get(url, headers=self.headers)

        if resp.status_code != 200:
            raise Exception(f"Failed retrieving permissions for role {role_id}: {resp.status_code} {resp.text}")

        role_data = resp.json()
        role_permissions = role_data.get("rolePermissions", [])

        granular_perms = []
        for perm in role_permissions:
            granular_perms.extend(perm.get("allowedResourceActions", []))

        return granular_perms

    def get_entraid_memberships(self):
        sub_resources = []
        sub_resources_tmp = []
        memberOf_url = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"

        try:
            member_objects = self.get_all_pages(memberOf_url)
            # If None, we don't have access to "/me" and therefore we cannot acces Entra ID permissions (in any case this happens in MI tokens)
            if member_objects is None:
                return None
        except Exception as e:
            print(f"Failed to retrieve memberOf data: {e}")
            return sub_resources

        def process_member_object(obj):
            odata_type = obj.get("@odata.type", "")
            obj_id = obj.get("roleTemplateId") or obj.get("id")
            name = obj.get("displayName") or obj_id
            permissions = ["Member"]

            if odata_type.endswith("directoryRole"):
                permissions = self.get_granular_permissions(obj_id)

                return {
                    "id": obj_id,
                    "name": name,
                    "type": odata_type,
                    "permissions": permissions,
                    "assignmentType": "Assigned"
                }

            return {} # Being a member is interesting but doesn't grant permissions as we get them recursively

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            results = executor.map(process_member_object, member_objects)

        sub_resources_tmp.extend(list(results))

        # Remove "{}"
        sub_resources = [x for x in sub_resources_tmp if x]

        # Check active roles (roles assigned over Administrative Units)
        user_id = self.get_my_user_id()
        url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '{user_id}'&$expand=roleDefinition"
        active_roles = self.get_all_pages(url)

        existing_role_ids = {entry["id"] for entry in sub_resources}

        for role in active_roles:
            directory_scope_id = role.get("directoryScopeId", "")
            role_definition_id = role.get("roleDefinitionId", "")

            if role_definition_id in existing_role_ids:
                continue

            granular_permissions = self.get_granular_permissions(role_definition_id)

            resource_entry = {
                "id": "roleDefinitionId:" + role_definition_id,
                "name": self.get_role_name(role_definition_id),
                "type": directory_scope_id,
                "permissions": granular_permissions,
                "assignmentType": "Assigned"
            }

            sub_resources.append(resource_entry)

        return sub_resources

    def get_assigned_permissions(self):
        """
        Fetch all direct + transitive Entra ID role assignments for the
        signed-in user and return, for each, the granular permissions.
        """

        user_id = self.get_my_user_id()

        url = (
            "https://graph.microsoft.com/beta/"
            "roleManagement/directory/transitiveRoleAssignments"
            "?$count=true"
            f"&$filter=principalId eq '{user_id}'"
        )

        assignments = self.get_all_pages(url)
        if not assignments:
            return []  # no assignments or no access

        results = []

        for a in assignments:
            rd_id = a.get("roleDefinitionId")
            try:
                perms = self.get_granular_permissions(rd_id)
            except Exception as e:
                # If we can’t fetch a roleDefinition, skip or log
                print(f"Failed to fetch perms for role {rd_id}: {e}")
                perms = []

            results.append({
                "id": "#microsoft.graph:" + "roleDefinitionId:" + a.get("roleDefinitionId"),
                "name": self.get_role_name(a.get("roleDefinitionId")),
                "type": a.get("directoryScopeId"),
                "permissions": perms,
                "assignmentType": "Assigned"
            })

        return results

    def get_my_app_role_assignments(self):
        """
        Fetches all app role assignments for the signed-in user and returns
        a list of dicts matching your other methods' format:
          - id
          - resourceId
          - resourceDisplayName
          - appRoleId
          - principalType
          - permissions  (granular, i.e. the role's 'value')
          - assignmentType ("Assigned")
        """

        url = "https://graph.microsoft.com/v1.0/me/appRoleAssignments"
        assignments = self.get_all_pages(url)
        if assignments is None:
            return []  # no access to /me or no assignments

        result = []
        for a in assignments:
            # Resolve granular appRole details from the service principal
            perms = self._get_app_role_value(a["resourceId"], a["appRoleId"])

            result.append({
                "id": "#microsoft.graph:" + a.get("resourceId") + "-" + a.get("resourceDisplayName") + "-" + a.get("principalType"),
                "name": a.get("appRoleId"),
                "type": "appRoleAssignment",
                "permissions": perms,
                "assignmentType": "Assigned"
            })

        return result

    def _get_app_role_value(self, resource_id, app_role_id):
        """
        Helper: fetches the service principal,
        finds the matching appRole, and returns its 'value' (name/permission).
        """
        url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{resource_id}"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code != 200:
            raise Exception(f"Failed to fetch SP {resource_id}: {resp.status_code} {resp.text}")

        sp = resp.json()
        for role in sp.get("appRoles", []):
            if role.get("id") == app_role_id:
                # return the human-readable permission name/value
                return role.get("value") or role.get("displayName")
        return []

    def get_eligible_roles(self):
        user_id = self.get_my_user_id()
        url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '{user_id}'&$expand=roleDefinition"

        try:
            eligible_roles = self.get_all_pages(url)
        except Exception as e:
            print(f"Failed to retrieve assignable roles data: {e}")
            return []

        eligible_resources = []

        for role in eligible_roles:
            role_definition_id = role.get("roleDefinitionId")
            role_name = role.get("roleDefinition", {}).get("displayName", role_definition_id)
            assignment_type = role.get("assignmentType")  # "Eligible"
            directory_scope = role.get("directoryScopeId")

            granular_permissions = self.get_granular_permissions(role_definition_id)

            eligible_resources.append({
                "id": role_definition_id,
                "name": role_name,
                "type": directory_scope,
                "permissions": granular_permissions,
                "assignmentType": assignment_type,
            })

        return eligible_resources    

    def get_entraid_owns(self):
        sub_resources = []
        # Retrieve the current principal’s owned objects (service principals, apps, groups that the principal owns)
        owned_objects_url = "https://graph.microsoft.com/v1.0/me/ownedObjects?$select=id,displayName,appDisplayName"
        owned_objects = self.get_all_pages(owned_objects_url)

        # Process each owned object
        for obj in owned_objects:
            odata_type = obj.get("@odata.type", "")
            obj_id = obj.get("id")
            name = obj.get("displayName") or obj.get("appDisplayName") or obj_id

            sub_resources.append({
                "id": obj_id,
                "name": name,
                "type": odata_type,
                "permissions": [f"Owner of {obj_id} ({odata_type})"]
            })
        
        return sub_resources
