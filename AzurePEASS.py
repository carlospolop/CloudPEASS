import argparse
import requests
import jwt
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.sensitive_permissions.azure import very_sensitive_combinations, sensitive_combinations
from src.azure.entraid import EntraIDPEASS

AZURE_MALICIOUS_RESPONSE_EXAMPLE = """[
    {
        "Title": "Privilege Escalationto arbitrary Managed Identities ",
        "Description": " Using the permissions Microsoft.Compute/virtualMachines/write and Microsoft.ManagedIdentity/userAssignedIdentities/assign/action among other it's possible to escalate privileges to arbitrary Managed Identities by creating a VM, assigning Managed Identities and then get tokens from the assigned Managed Identities from the metadata.",
        "Commands": "az vm create \\
                --resource-group Resource_Group_1 \\
                --name cli_vm \\
                --image Ubuntu2204 \\
                --admin-username azureuser \\
                --generate-ssh-keys \\
                --assign-identity /subscriptions/<sub-id>/resourcegroups/<res-group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<mi-name> \\
                --nsg-rule ssh \\
                --location centralus"
    },
    [...]
]"""


AZURE_SENSITIVE_RESPONSE_EXAMPLE = """[
    {
        "permission": "Microsoft.Web/sites/host/listkeys/action",
        "is_very_sensitive": true,
        "is_sensitive": false,
        "description": "This permission allows to list the keys of a web app, which can be used to access sensitive information and modify the code and escalate privleges to the managed identity."
    },
    [...]
]"""

class AzurePEASS(CloudPEASS):
    def __init__(self, arm_token, graph_token, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path=None):
        self.arm_token= arm_token
        self.graph_token = graph_token
        self.EntraIDPEASS = EntraIDPEASS(graph_token, num_threads)
        super().__init__(very_sensitive_combos, sensitive_combos, "Azure", not_use_ht_ai, num_threads, AZURE_MALICIOUS_RESPONSE_EXAMPLE, AZURE_SENSITIVE_RESPONSE_EXAMPLE, out_path)

        if not self.arm_token and not self.graph_token:
            raise ValueError("At lest an ARM token or Graph token is needed")

        if self.arm_token:
            self.check_jwt_token(self.arm_token, ["https://management.azure.com/", "https://management.core.windows.net/"])

        # Check Graph token
        if graph_token:
            self.check_jwt_token(self.graph_token, ["https://graph.microsoft.com/", "00000003-0000-0000-c000-000000000000"])

    
    def check_jwt_token(self, token, expected_audiences):
        try:
            # Decode the token without verifying the signature
            decoded = jwt.decode(token, options={"verify_signature": False})

            # Check if "aud" matches
            if decoded.get("aud") not in expected_audiences:
                raise ValueError(f"Invalid audience. Expected '{expected_audiences}', got '{decoded.get('aud')}'")

            # Check if token has expired
            current_time = int(time.time())
            if decoded.get("exp", 0) < current_time:
                raise ValueError("Token has expired")

            return True

        except jwt.DecodeError:
            raise ValueError("Token is invalid or badly formatted")


    def list_subscriptions(self):
        url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
        resp = requests.get(url, headers={"Authorization": f"Bearer {self.arm_token}"})
        resp.raise_for_status()
        subs = [sub["subscriptionId"] for sub in resp.json().get("value", [])]
        return subs

    def list_resources_in_subscription(self, subscription_id):
        resources = []
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
        resp = requests.get(url, headers={"Authorization": f"Bearer {self.arm_token}"})
        if resp.status_code != 200:
            return resources
        data = resp.json()
        resources.extend(data.get("value", []))
        while "nextLink" in data:
            next_url = data["nextLink"]
            resp = requests.get(next_url, headers={"Authorization": f"Bearer {self.arm_token}"})
            resp.raise_for_status()
            data = resp.json()
            resources.extend(data.get("value", []))
        return resources

    def get_permissions_for_resource(self, resource_id):
        perms = set()

        # Retrieve active permissions
        permissions_url = f"https://management.azure.com{resource_id}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
        resp = requests.get(permissions_url, headers={"Authorization": f"Bearer {self.arm_token}"})
        if resp.status_code != 200:
            raise Exception(f"Failed fetching permissions: {resp.text}")

        perm_data = resp.json().get('value', [])
        for perm_block in perm_data:
            actions = set(perm_block.get("actions", []))
            data_actions = set(perm_block.get("dataActions", []))
            not_actions = set(perm_block.get("notActions", []))
            not_data_actions = set(perm_block.get("notDataActions", []))

            perms.update(actions - not_actions)
            perms.update(data_actions - not_data_actions)

        # Retrieve eligible roles for the resource
        eligible_roles_url = f"https://management.azure.com{resource_id}/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&$filter=asTarget()"
        resp_eligible = requests.get(eligible_roles_url, headers={"Authorization": f"Bearer {self.arm_token}"})

        if resp_eligible.status_code == 200:
            eligible_roles = resp_eligible.json().get('value', [])
            for eligible in eligible_roles:
                role_definition_id = eligible['properties']['roleDefinitionId']

                # Fetch granular permissions for each eligible role
                role_def_url = f"https://management.azure.com{role_definition_id}?api-version=2022-04-01"
                resp_role = requests.get(role_def_url, headers={"Authorization": f"Bearer {self.arm_token}"})

                if resp_role.status_code == 200:
                    role_properties = resp_role.json().get("properties", {})
                    role_permissions = role_properties.get("permissions", [])
                    
                    for perm_block in role_permissions:
                        actions = set(perm_block.get("actions", []))
                        data_actions = set(perm_block.get("dataActions", []))
                        not_actions = set(perm_block.get("notActions", []))
                        not_data_actions = set(perm_block.get("notDataActions", []))

                        perms.update(actions - not_actions)
                        perms.update(data_actions - not_data_actions)

        else:
            print(f"Unable to retrieve eligible roles: {resp_eligible.status_code} {resp_eligible.text}")

        return list(perms)


    def get_resources_and_permissions(self):
        resources_data = []
        subs = self.list_subscriptions()

        def process_subscription(sub_id):
            sub_resources = []
            raw_resources = self.list_resources_in_subscription(sub_id)

            perms = self.get_permissions_for_resource(f"/subscriptions/{sub_id}")
            if perms:
                sub_resources.append({
                    "id": f"/subscriptions/{sub_id}",
                    "name": sub_id,
                    "type": "subscription",
                    "permissions": perms
                })

            for res in raw_resources:
                res_id = res.get("id")
                res_name = res.get("name")
                res_type = res.get("type")
                perms = self.get_permissions_for_resource(res_id)
                sub_resources.append({
                    "id": res_id,
                    "name": res_name,
                    "type": res_type,
                    "permissions": perms
                })
            return sub_resources

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            results = list(tqdm(executor.map(process_subscription, subs), total=len(subs), desc="Processing Subscriptions"))

        for sub_result in results:
            resources_data.extend(sub_result)

        print("Analyzing Permissions from EntraID...")
        resources_data += self.EntraIDPEASS.get_entraid_memberships()
        resources_data += self.EntraIDPEASS.get_eligible_roles()
        resources_data += self.EntraIDPEASS.get_entraid_owns()

        return resources_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run AzurePEASS to find all your current privileges in Azure and EntraID and check for potential privilege escalation attacks.\nTo check for Azure permissions an ARM token is neded.\nTo check for Entra ID permissions a Graph token is needed.")
    parser.add_argument('--arm-token', help="Azure Management authentication token")
    parser.add_argument('--graph-token', help="Azure Graph authentication token")
    parser.add_argument('--out', default=None, help="Output JSON file path (e.g. /tmp/azure_results.json)")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_false", default=False, help="Don't use Hacktricks AI to analyze permissions")

    args = parser.parse_args()

    azure_peass = AzurePEASS(args.arm_token, args.graph_token, very_sensitive_combinations, sensitive_combinations, not_use_ht_ai=args.not_use_hacktricks_ai, num_threads=args.threads, out_path=args.out)
    azure_peass.run_analysis()