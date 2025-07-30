import argparse
import requests
import jwt
import time
import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style, init, Back
import msal
import re

init(autoreset=True)

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.sensitive_permissions.azure import very_sensitive_combinations, sensitive_combinations
from src.azure.entraid import EntraIDPEASS
from src.azure.definitions import SHAREPOINT_FOCI_APPS, ONEDRIVE_FOCI_APPS, EMAIL_FOCI_APPS, TEAMS_FOCI_APPS_GRAPH, TEAMS_FOCI_APPS_SKYPE, ONENOTE_FOCI_APPS, CONTACTS_FOCI_APPS, TASKS_FOCI_APPS, FOCI_APPS

AZURE_MALICIOUS_RESPONSE_EXAMPLE = """[
    {
        "Title": "Privilege Escalation to arbitrary Managed Identities",
        "Description": "Using the permissions Microsoft.Compute/virtualMachines/write and Microsoft.ManagedIdentity/userAssignedIdentities/assign/action among others it's possible to escalate privileges to arbitrary Managed Identities by creating a VM, assigning Managed Identities and then get tokens from the assigned Managed Identities from the metadata.",
        "Commands": "az vm create \\
                --resource-group Resource_Group_1 \\
                --name cli_vm \\
                --image Ubuntu2204 \\
                --admin-username azureuser \\
                --generate-ssh-keys \\
                --assign-identity /subscriptions/<sub-id>/resourcegroups/<res-group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<mi-name> \\
                --nsg-rule ssh \\
                --location centralus",
        "Permissions": [
            "Microsoft.Compute/virtualMachines/write",
            "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
        ],
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

AZURE_CLARIFICATIONS = """- The permission "Microsoft.KeyVault/vaults/secrets/read" allows to list secrets but not to read them. To read asecret you need the permission "Microsoft.KeyVault/vaults/secrets/getSecret/action"."""



class AzurePEASS(CloudPEASS):
    def __init__(self, arm_token, graph_token, foci_refresh_token, tenant_id, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, not_enumerate_m365, out_path=None, check_only_subs=[]):
        self.foci_refresh_token = foci_refresh_token
        self.tenant_id = tenant_id
        self.not_enumerate_m365 = not_enumerate_m365

        if self.foci_refresh_token:
            if not self.tenant_id:
                print(f"{Fore.RED}Tenant ID is required when using FOCI refresh token. Indicate it with --tenant-id. Exiting.")
                exit(1)
            # Get ARM and Graph tokens from FOCI refresh token
            arm_token = self.get_tokens_from_foci(["https://management.azure.com/.default"])
            graph_token = self.get_tokens_from_foci(["https://graph.microsoft.com/.default"])

        self.arm_token= arm_token
        self.graph_token = graph_token
        self.EntraIDPEASS = EntraIDPEASS(graph_token, num_threads)
        self.sharepoint_followed_sites_ids = []
        self.initial_subscriptions = []
        self.check_only_subs = check_only_subs
        super().__init__(very_sensitive_combos, sensitive_combos, "Azure", not_use_ht_ai, num_threads, AZURE_MALICIOUS_RESPONSE_EXAMPLE, AZURE_SENSITIVE_RESPONSE_EXAMPLE, AZURE_CLARIFICATIONS, out_path)

        if not self.arm_token and not self.graph_token:
            if self.foci_refresh_token:
                print(f"{Fore.RED}It wasn't possible to generate an ARM or Graph token with that FOCI token, it's potentially malformed. Exiting..")
            else:
                print(f"{Fore.RED}At least an ARM token or Graph token is needed. Exiting.")
            exit(1)
        
        if not self.arm_token:
            print(f"{Fore.RED}ARM token not provided. Skipping Azure permissions analysis")
        
        if not self.graph_token:
            print(f"{Fore.RED}Graph token not provided. Skipping EntraID permissions analysis. If App creds, it might have Entra ID roles or API permissions of type 'application' that I cannot lest.")

        if self.arm_token:
            self.check_jwt_token(self.arm_token, ["https://management.azure.com/", "https://management.core.windows.net/", "https://management.azure.com"])

        if self.graph_token:
            self.check_jwt_token(self.graph_token, ["https://graph.microsoft.com/", "00000003-0000-0000-c000-000000000000", "https://graph.microsoft.com"])

    
    def check_jwt_token(self, token, expected_audiences):
        try:
            # Decode the token without verifying the signature
            decoded = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})

            # Check if "aud" matches
            if decoded.get("aud") not in expected_audiences:
                raise ValueError(f"Invalid audience. Expected '{expected_audiences}', got '{decoded.get('aud')}'")

            # Check if token has expired
            current_time = int(time.time() + 30) # Extra 30 secs to account for clock skew
            if decoded.get("exp", 0) < current_time:
                raise ValueError(f"Token {decoded.get('exp')} has expired")

            return True

        except jwt.DecodeError:
            raise ValueError("Token is invalid or badly formatted")


    def list_subscriptions(self):
        if self.check_only_subs:
            # If check_only_subs is provided, return only those subscriptions
            return self.check_only_subs
        
        url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
        resp = requests.get(url, headers={"Authorization": f"Bearer {self.arm_token}"})
        subs = [sub["subscriptionId"] for sub in resp.json().get("value", [])]
        for sub in self.initial_subscriptions:
            if sub not in subs:
                subs.append(sub)
        return subs

    def list_resources_in_subscription(self, subscription_id):
        resources = []
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
        resp = requests.get(url, headers={"Authorization": f"Bearer {self.arm_token}"})
        if resp.status_code != 200:
            return resources
        data = resp.json()
        resources.extend(data.get("value", []))
        cont = 0
        while "nextLink" in data and cont <= 30:  # Limit to 30 pages to avoid infinite loops
            next_url = data["nextLink"]
            resp = requests.get(next_url, headers={"Authorization": f"Bearer {self.arm_token}"})
            data = resp.json()
            resources.extend(data.get("value", []))
            cont += 1
        
        if cont > 30:
            print(f"{Fore.RED}Warning: More than 30 pages of resources found in subscription {subscription_id}. Stopping enumeration to avoid too long enumeration but some permissions will be missed!")
        
        return resources

    def get_permissions_for_resource(self, resource_id, cont=0):
        perms = set()

        # Retrieve active permissions
        permissions_url = f"https://management.azure.com{resource_id}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
        resp = requests.get(permissions_url, headers={"Authorization": f"Bearer {self.arm_token}"})
        if resp.status_code == 429:
            if cont > 5:
                print(f"{Fore.RED}Rate limit exceeded while fetching permissions for {resource_id}. Exiting after 5 retries.")
                return []
            
            print(f"{Fore.RED}Rate limit exceeded while fetching permissions for {resource_id}. Retrying after 30 seconds...")
            time.sleep(30)
            return self.get_permissions_for_resource(resource_id, cont + 1)
        
        if resp.status_code != 200:
            if resp.status_code == 403:
                # If 403, the user doesn't have IAM permissions inside the subscription
                # The error message might say something like: does not have authorization to perform action \'Microsoft.Authorization/permissions/read\' over scope \'/subscriptions/6414b7ad-ea28-41d3-901e-3132c02d7b0a\' or the scope is invalid
                # But actually that permission shouldn't be needed (or maybe is granted if you have some permissions inside the subscription)
                # So we will just put that the permissions are empty
                perm_data = []
            else:
                raise Exception(f"Failed fetching permissions: {resp.text}")

        else:
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
            print(f"Unable to retrieve eligible roles: {resp_eligible.status_code} {resp_eligible.text} ( This is common, you need an Azure permission to list eligible roles )")

        return list(perms)
    
    def print_whoami_info(self):
        """
        Prints the current principal information.
        This is useful for debugging and understanding the context of the permissions being analyzed.
        """

        if self.arm_token:
            try:
                # Get also email and groups
                decoded = jwt.decode(self.arm_token, options={"verify_signature": False, "verify_aud": False})
                print(f"{Fore.BLUE}Current Principal ID (ARM Token): {Fore.WHITE}{decoded.get('oid', 'Unknown')}")
                print(f"{Fore.BLUE}Current Audience (ARM Token): {Fore.WHITE}{decoded.get('aud', 'Unknown')}")
                if 'upn' in decoded:
                    print(f"{Fore.BLUE}User Principal Name (UPN) (ARM Token): {Fore.WHITE}{decoded.get('upn', 'Unknown')}")
                if 'email' in decoded:
                    print(f"{Fore.BLUE}Email (ARM Token): {Fore.WHITE}{decoded.get('email', 'Unknown')}")
                if 'groups' in decoded:
                    groups = decoded.get('groups', [])
                    print(f"{Fore.BLUE}Groups (ARM Token): {Fore.WHITE}{', '.join(groups) if groups else 'None'}")
                if 'exp' in decoded:
                    expiration_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(decoded.get('exp')))
                    print(f"{Fore.BLUE}Token Expiration Time (ARM Token): {Fore.WHITE}{expiration_time}")
                # Use a regex to find subscriptions IDs from the token
                self.initial_subscriptions = list(set(re.findall(r"subscriptions/([a-z0-9-]+)", str(decoded))))
                if self.initial_subscriptions:
                    print(f"{Fore.BLUE}Initial Subscriptions: {Fore.WHITE}{', '.join(self.initial_subscriptions)}")
                print()
            except Exception as e:
                print(f"{Fore.RED}Failed to decode ARM token: {str(e)}")
        
        if self.graph_token:
            try:
                # Decode the Graph token to get the current principal information
                decoded = jwt.decode(self.graph_token, options={"verify_signature": False, "verify_aud": False})
                print(f"{Fore.BLUE}Current Principal ID (Graph Token): {Fore.WHITE}{decoded.get('oid', 'Unknown')}")
                print(f"{Fore.BLUE}Current Audience (Graph Token): {Fore.WHITE}{decoded.get('aud', 'Unknown')}")
                if 'upn' in decoded:
                    print(f"{Fore.BLUE}User Principal Name (UPN) (Graph Token): {Fore.WHITE}{decoded.get('upn', 'Unknown')}")
                if 'email' in decoded:
                    print(f"{Fore.BLUE}Email (Graph Token): {Fore.WHITE}{decoded.get('email', 'Unknown')}")
                if 'groups' in decoded:
                    groups = decoded.get('groups', [])
                    print(f"{Fore.BLUE}Groups (Graph Token): {Fore.WHITE}{', '.join(groups) if groups else 'None'}")
                if 'exp' in decoded:
                    expiration_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(decoded.get('exp')))
                    print(f"{Fore.BLUE}Token Expiration Time (Graph Token): {Fore.WHITE}{expiration_time}")
                
                print(f"{Fore.YELLOW}\nEnumerating Conditional Access Policies:{Fore.RESET}")
                self.enumerate_conditional_access_policies(self.graph_token)
            except Exception as e:
                print(f"{Fore.RED}Failed to decode Graph token: {str(e)}")
        
        if self.foci_refresh_token and not self.not_enumerate_m365:
            # SHAREPOINT
            print(f"{Fore.YELLOW}\nEnumerating SharePoint files | max depth 3 | top 10 {Fore.RESET}(Thanks to {Fore.BLUE}JoelGMSec{Fore.RESET} for the idea):")
            sharepoint_token = self.get_tokens_from_foci_with_scope(SHAREPOINT_FOCI_APPS)

            if sharepoint_token:
                self.sharepoint_enumerate_followed_sites(sharepoint_token)
                self.sharepoint_enumerate_public_sites(sharepoint_token)
            
            # ONEDRIVE
            print(f"{Fore.YELLOW}\nEnumerating onedrive | max depth 3 | top 10:")
            onedrive_token = self.get_tokens_from_foci_with_scope(ONEDRIVE_FOCI_APPS)

            if onedrive_token:
                self.enumerate_onedrive(onedrive_token, max_depth=3)
            
            # EMAILS
            print(f"{Fore.YELLOW}\nEnumerating Emails:")
            mail_read_token = self.get_tokens_from_foci_with_scope(EMAIL_FOCI_APPS)

            if mail_read_token:
                self.enumerate_emails(mail_read_token)
            else:
                print(f"{Fore.RED}No FOCI app with Mail.Read scope found. Skipping email enumeration.{Fore.WHITE}")

            # TEAMS
            print(f"{Fore.YELLOW}\nEnumerating Teams Conversations:")
            teams_token_skype = self.get_tokens_from_foci_with_scope(TEAMS_FOCI_APPS_SKYPE)
            teams_token_graph = self.get_tokens_from_foci_with_scope(TEAMS_FOCI_APPS_GRAPH)

            if teams_token_skype or teams_token_graph:
                self.enumerate_teams_conversations(teams_token_skype, teams_token_graph)
            else:
                print(f"{Fore.RED}No FOCI app with Teams or Skype scopes found. Skipping Teams conversations enumeration.{Fore.WHITE}")

            # ONENOTE
            print(f"{Fore.YELLOW}\nEnumerating OneNote Notebooks and Sections:")
            onenote_token = self.get_tokens_from_foci_with_scope(ONENOTE_FOCI_APPS)

            # If token is successfully retrieved, enumerate OneNote content
            if onenote_token:
                self.enumerate_onenote_content(onenote_token)
            else:
                print(f"{Fore.RED}No FOCI app with OneNote scopes found. Skipping OneNote enumeration.{Fore.WHITE}")

            # CONTACTS
            print(f"{Fore.YELLOW}\nEnumerating Contacts:")
            contacts_token = self.get_tokens_from_foci_with_scope(CONTACTS_FOCI_APPS)

            if contacts_token:
                self.enumerate_contacts(contacts_token)
            else:
                print(f"{Fore.RED}No FOCI app with Contacts scopes found. Skipping Contacts enumeration.{Fore.WHITE}")
            
            # TASKS
            print(f"{Fore.YELLOW}\nEnumerating Tasks:")
            tasks_token = self.get_tokens_from_foci_with_scope(TASKS_FOCI_APPS)
            
            if tasks_token:
                self.enumerate_tasks(tasks_token)
            else:
                print(f"{Fore.RED}No FOCI app with Tasks scopes found. Skipping Tasks enumeration.{Fore.WHITE}")


    def enumerate_conditional_access_policies(self, graph_token):
        """
        List all Conditional Access policies via Microsoft Graph.
        """

        headers = {'Authorization': f'Bearer {graph_token}'}
        url = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
        while url:
            resp = requests.get(url, headers=headers)
            if resp.status_code == 403 or resp.status_code == 401:
                print(f"{Fore.RED}Your user doesn't have access to read the conditional access policies.")
                break
            
            data = resp.json()
            for policy in data.get('value', []):
                print(f"{Fore.CYAN}Policy: {Fore.WHITE}{policy.get('displayName')}")
                print(f"{Fore.CYAN}State: {Fore.WHITE}{policy.get('state')}")
                # Show key rule details
                conditions = policy.get('conditions', {})
                print(f"{Fore.CYAN}Conditions: {Fore.WHITE}{conditions}")
                grant_ctrls = policy.get('grantControls', {})
                print(f"{Fore.CYAN}Grant Controls: {Fore.WHITE}{grant_ctrls}")
                print("-" * 50)
            # Follow pagination if present
            url = data.get('@odata.nextLink')

    
    def enumerate_tasks(self, tasks_token):
        headers = {'Authorization': f'Bearer {tasks_token}'}
        lists_url = 'https://graph.microsoft.com/v1.0/me/todo/lists?$top=10'

        while lists_url:
            resp = requests.get(lists_url, headers=headers)
            data = resp.json()
            
            for todo_list in data.get('value', []):
                print(f"{Fore.BLUE}- List: {Fore.WHITE}{todo_list['displayName']}")
                # Enumerate tasks within the current To-Do list
                tasks_url = f"https://graph.microsoft.com/v1.0/me/todo/lists/{todo_list['id']}/tasks?$top=10"
                tasks_resp = requests.get(tasks_url, headers=headers)
                tasks_data = tasks_resp.json()
                
                for task in tasks_data.get('value', []):
                    title = task.get('title', 'No Title')
                    status = task.get('status', 'N/A')
                    importance = task.get('importance', 'N/A')
                    body = task.get('body', {}).get("content", "")
                    print(f"    {Fore.CYAN}- Task: {Fore.WHITE}{title} ({Fore.CYAN}Status: {Fore.WHITE}{status}) ({Fore.CYAN}Importance: {Fore.WHITE}{importance})")
                    if body:
                        print(f"        {Fore.CYAN}Body: {Fore.WHITE}{str(body)}")
            
            # Handle pagination for To-Do lists
            if '@odata.nextLink' in data:
                cont = input("Show more To-Do lists? (y/n): ")
                if cont.lower() != 'y':
                    break
                lists_url = data['@odata.nextLink']
            else:
                break
    
    def enumerate_contacts(self, contacts_token):
        headers = {'Authorization': f'Bearer {contacts_token}'}
        contacts_url = 'https://graph.microsoft.com/v1.0/me/contacts?$top=10'
        
        while contacts_url:
            resp = requests.get(contacts_url, headers=headers)
            data = resp.json()
            
            for contact in data.get('value', []):
                name = contact.get('displayName', contact.get('givenName', 'No Name'))
                phones = list(set(contact.get('homePhones', []) + [contact.get('mobilePhone', "")] + contact.get('businessPhones', [])))
                emails = contact.get('emailAddresses', [])
                print(f"{Fore.BLUE}Name: {Fore.WHITE}{str(name)}")
                print(f"{Fore.BLUE}Phones: {Fore.WHITE}{str(phones)}")
                print(f"{Fore.BLUE}Emails: {Fore.WHITE}{str(emails)}")
                print("-" * 50)
            
            # Handle pagination if there's more data
            if '@odata.nextLink' in data:
                cont = input("Show more Contacts? (y/N): ")
                if cont.lower() != 'y':
                    break
                contacts_url = data['@odata.nextLink']
            else:
                break
    
    def enumerate_onenote_content(self, onenote_token):
        headers = {'Authorization': f'Bearer {onenote_token}'}
        notebooks_url = 'https://graph.microsoft.com/v1.0/me/onenote/notebooks?$top=10'
        
        # Loop through notebooks pages if paginated
        while notebooks_url:
            resp = requests.get(notebooks_url, headers=headers)
            data = resp.json()
            
            for notebook in data.get('value', []):
                print(f"{Fore.BLUE}Notebook: {Fore.WHITE}{notebook['displayName']}")
                print(f"{Fore.BLUE}Role: {Fore.WHITE}{notebook['userRole']}")
                print(f"{Fore.BLUE}Is Shared?: {Fore.WHITE}{notebook['isShared']}")
                print(f"{Fore.BLUE}Last Modified: {Fore.WHITE}{notebook['lastModifiedDateTime']}")
                print(f"{Fore.BLUE}Created by: {Fore.WHITE}{notebook['createdBy']['user']['displayName']}")
                print("-" * 50)
                
                # Enumerate Sections within each Notebook
                sections_url = f"https://graph.microsoft.com/v1.0/me/onenote/notebooks/{notebook['id']}/sections"
                sections_resp = requests.get(sections_url, headers=headers)
                sections_data = sections_resp.json()
                
                for section in sections_data.get('value', []):
                    print(f"    {Fore.BLUE}- Section: {section['displayName']} (ID: {section['id']})")
            
            # Check if there's more data to paginate
            if '@odata.nextLink' in data:
                cont = input("Show more OneNote Notebooks? (y/N): ")
                if cont.lower() != 'y':
                    break
                notebooks_url = data['@odata.nextLink']
            else:
                break

    def fetch_paginated_data(self, url, token):
        """Helper to retrieve all paginated data from a Graph API endpoint."""
        headers = {'Authorization': f'Bearer {token}'}
        items = []
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            items.extend(data.get("value", []))
            url = data.get('@odata.nextLink') or data.get('nextLink')
        return items


    def enumerate_site(self, site, token, indent=""):
        """Print details of a single site and enumerate its documents."""
        name = site.get("displayName") or site.get("name", "Unnamed")
        web_url = site.get("webUrl", "No URL provided")
        site_id = site.get("id")
        print(f"{indent}- {Fore.YELLOW}Site:{Fore.RESET} {name} | {Fore.BLUE}{web_url}")
        self.sharepoint_list_documents(site_id, token, indent + "  ")

    def sharepoint_enumerate_followed_sites(self, token, depth=1, max_depth=3, url="https://graph.microsoft.com/v1.0/me/followedSites"):
        """Recursively enumerate followed sites."""

        if depth == 1:
            print(f"\n{Fore.CYAN}Followed Sites:{Fore.RESET}")
        headers = {'Authorization': f'Bearer {token}'}
        indent = "  " * (depth - 1)
        
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            for site in data.get("value", []):
                self.sharepoint_followed_sites_ids.append(site.get("id"))
                self.enumerate_site(site, token, indent)
                if depth < max_depth:
                    subsites_url = f"https://graph.microsoft.com/v1.0/sites/{site.get('id')}/sites?$top=10"
                    self.sharepoint_enumerate_followed_sites(token, depth + 1, max_depth, subsites_url)
            url = data.get('@odata.nextLink') or data.get('nextLink')

    def sharepoint_list_documents(self, site_id, token, indent="", depth=1, max_depth=3):
        """List documents in the default document library of a site."""
        headers = {'Authorization': f'Bearer {token}'}
        url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root/children?$top=10"
        print(f"{indent}Documents:")
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            for item in data.get("value", []):
                item_name = item.get("name", "Unnamed item")
                if "folder" in item:
                    print(f"{indent}  - {Fore.MAGENTA}Folder: {Fore.RESET}{item_name}")
                    if depth < max_depth:
                        self.sharepoint_list_folder_contents(
                        site_id,
                        token,
                        item.get("id"),
                        indent + "    "
                    )
                else:
                    size = item.get("size", "Unknown")
                    last_modified = item.get("lastModifiedDateTime", "Unknown")
                    print(f"{indent}- {Fore.GREEN}File: {Fore.RESET}{item_name} | {Fore.CYAN}Size:{Fore.RESET} {size} bytes | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}")
            url = data.get('@odata.nextLink') or data.get('nextLink')

    def sharepoint_list_folder_contents(self, site_id, token, folder_id, indent=""):
        """Recursively list folder contents."""
        headers = {'Authorization': f'Bearer {token}'}
        url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{folder_id}/children?$top=10"
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            for item in data.get("value", []):
                item_name = item.get("name", "Unnamed item")
                if "folder" in item:
                    print(f"{indent}- {Fore.BLUE}Folder: {Fore.RESET}{item_name}")
                    self.sharepoint_list_folder_contents(site_id, token, item.get("id"), indent + "  ")
                else:
                    size = item.get("size", "Unknown")
                    last_modified = item.get("lastModifiedDateTime", "Unknown")
                    print(f"{indent}- {Fore.GREEN}File: {Fore.RESET}{item_name} | {Fore.CYAN}Size:{Fore.RESET} {size} bytes | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}")
            url = data.get('@odata.nextLink') or data.get('nextLink')

    def sharepoint_enumerate_public_sites(self, token):
        """Enumerate public sites not already followed by the current user."""
        url = "https://graph.microsoft.com/v1.0/sites?search=*"
        print(f"\n{Fore.CYAN}Public Sites:{Fore.RESET}")
        while url:
            response = requests.get(url, headers={'Authorization': f'Bearer {token}'})
            data = response.json()
            for site in data.get("value", []):
                if site.get("id") in self.sharepoint_followed_sites_ids:
                    continue
                self.enumerate_site(site, token, indent="")  # No extra indentation for public sites
            url = data.get('@odata.nextLink') or data.get('nextLink')

    def enumerate_emails(self, outlook_token):
        headers = {'Authorization': f'Bearer {outlook_token}'}
        mail_url = 'https://graph.microsoft.com/v1.0/me/messages?$top=10'

        while mail_url:
            resp = requests.get(mail_url, headers=headers)
            data = resp.json()
            
            for message in data.get('value', []):
                subject = message.get('subject', 'N/A')
                from_email = message.get('from', {}).get('emailAddress', {}).get('address', 'N/A')
                body_preview = message.get('bodyPreview', 'N/A')
                web_link = message.get('webLink', 'N/A')

                print(f"{Fore.BLUE}Email Subject: {Fore.WHITE}{subject}")
                print(f"{Fore.BLUE}From Email: {Fore.WHITE}{from_email}")
                print(f"{Fore.BLUE}Snippet: {Fore.WHITE}{body_preview}")
                print(f"{Fore.BLUE}Link: {Fore.WHITE}{web_link}")
                print("-" * 50)

            if '@odata.nextLink' in data:
                cont = input("Show more Emails? (y/N): ")
                if cont.lower() != 'y':
                    break
                mail_url = data['@odata.nextLink']
            else:
                break
    
    def enumerate_teams_conversations(self, teams_token_skype, teams_token_graph):
        # Get Skype token
        if not teams_token_skype:
            print(f"{Fore.RED}No FOCI app with Skype scopes found. Skipping conversations enumeration.{Fore.WHITE}")
            
        else:
            headers = {'Authorization': f'Bearer {teams_token_skype}'}
            url = "https://teams.microsoft.com/api/authsvc/v1.0/authz"
            resp = requests.post(url, headers=headers)
            data = resp.json()
            skype_token = data.get("tokens", {}).get("skypeToken")
            chat_service_uri = data.get("regionGtms", {}).get("chatService")

            if not chat_service_uri:
                print(f"{Fore.RED}No access to chats.")
                return
            
            # Get open conversations
            headers = {"Authentication":f"skypetoken={skype_token}", 'Authorization': f'Bearer {teams_token_skype}'}
            url = f"{chat_service_uri}/v1/users/ME/conversations?view=msnp24Equivalent&pageSize=500"
            resp = requests.get(url, headers=headers)
            data = resp.json()

            if not data.get("conversations"):
                print(f"{Fore.GREEN}No conversations found in Teams.{Fore.WHITE}")
            else:
                print(f"{Fore.GREEN}Some conversations found in Teams:{Fore.WHITE}")
                for conversation in data.get("conversations", []):
                    conv_id = conversation.get("id")
                    conv_role = conversation.get("memberProperties", {}).get("role")
                    conv_type = conversation.get("type")
                    last_message = conversation.get("lastMessage", {})
                    last_message_content = last_message.get("content", "")
                    last_message_from = last_message.get("fromDisplayNameInToken", "") if last_message.get("fromDisplayNameInToken", "") else last_message.get("imdisplayname", "Unkown")
                    
                    print(f"{Fore.BLUE}  Conversation ID: {Fore.WHITE}{conv_id}")
                    print(f"{Fore.BLUE}  Role: {Fore.WHITE}{conv_role}")
                    print(f"{Fore.BLUE}  Type: {Fore.WHITE}{conv_type}")
                    print(f"{Fore.BLUE}  Last Message {Fore.GREEN}(from {last_message_from}): {Fore.WHITE}{last_message_content}")
                    print()

        # Enumerate Joined Teams (Groups)
        if not teams_token_graph:
            print(f"{Fore.RED}No FOCI app with Teams scopes found. Skipping teams enumeration.{Fore.WHITE}")
        
        else:
            headers = {'Authorization': f'Bearer {teams_token_graph}'}
            teams_url = 'https://graph.microsoft.com/v1.0/me/joinedTeams'
            while teams_url:
                resp = requests.get(teams_url, headers=headers)
                data = resp.json()
                if data.get('value', []):
                    print(f"{Fore.GREEN}Some teams found in Teams:{Fore.WHITE}")
                    for team in data.get('value', []):
                        print(f"{Fore.BLUE}  Team: {Fore.WHITE}{team['displayName']}")
                        print(f"{Fore.BLUE}  Description: {Fore.WHITE}{team['description']}")
                        print()
                    if '@odata.nextLink' in data:
                        cont = input("Show more Joined Teams? (y/N): ")
                        if cont.lower() != 'y':
                            break
                        teams_url = data['@odata.nextLink']
                    else:
                        break
                
                else:
                    print(f"{Fore.GREEN}No teams found in Teams.{Fore.WHITE}")
                    break

    def enumerate_onedrive(self, onedrive_token, max_depth=3):
        # Root URL to list items in the root folder
        root_url = "https://graph.microsoft.com/v1.0/me/drive/root/children?$top=10"
        self._list_items(root_url, onedrive_token, depth=1, max_depth=max_depth)

    def _list_items(self, url, token, depth, max_depth):
        headers = {'Authorization': f'Bearer {token}'}
        # Indentation for hierarchical display
        indent = "  " * (depth - 1)
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            for item in data.get('value', []):
                name = item.get('name', 'Unnamed')
                last_modified = item.get('lastModifiedDateTime', 'Unknown')
                web_url = item.get('webUrl', 'Unknown')
                # Determine the type of the item
                if 'folder' in item:
                    child_count = item['folder'].get('childCount', 0)
                    special_folder = item['folder'].get('specialFolder', {}).get('name', '')
                    if special_folder:
                        msg = f"{indent}- {Fore.MAGENTA}Folder: {Fore.RESET}{name} | {Fore.CYAN}Special folder:{Fore.RESET} {special_folder} | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}"
                    else:
                        msg = f"{indent}- {Fore.MAGENTA}Folder: {Fore.RESET}{name} | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}"
                    print(msg)
                    
                    # Recursive call for folder contents if max_depth is not reached
                    if depth < max_depth:
                        folder_children_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{item['id']}/children?$top=50"
                        self._list_items(folder_children_url, token, depth + 1, max_depth)
                
                else:
                    size = item.get('size', 'Unknown')
                    print(f"{indent}- {Fore.GREEN}File: {Fore.RESET}{name} | {Fore.CYAN}Size: {Fore.RESET}{size} | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}")
            
            # Handle pagination: continue if a next page exists
            next_link = data.get('@odata.nextLink') or data.get('nextLink')
            if next_link:
                url = next_link
            else:
                break

    def get_resources_and_permissions(self):
        resources_data = []

        if self.arm_token:
            subs = self.list_subscriptions()

            def process_subscription(sub_id):
                sub_resources = []
                raw_resources = self.list_resources_in_subscription(sub_id)

                # Add subscription permissions
                perms = self.get_permissions_for_resource(f"/subscriptions/{sub_id}")
                if perms:
                    sub_resources.append({
                        "id": f"/subscriptions/{sub_id}",
                        "name": sub_id,
                        "type": "subscription",
                        "permissions": perms
                    })

                # Process resources in parallel with progress bar
                def get_resource_permissions(res):
                    res_id = res.get("id")
                    res_name = res.get("name")
                    res_type = res.get("type")
                    perms = self.get_permissions_for_resource(res_id)
                    return {
                        "id": res_id,
                        "name": res_name,
                        "type": res_type,
                        "permissions": perms
                    }

                if raw_resources:
                    # Use 3 threads for permission fetching per subscription
                    with ThreadPoolExecutor(max_workers=min(3, max(1, len(raw_resources) // 10))) as resource_executor:
                        resource_results = list(tqdm(
                            resource_executor.map(get_resource_permissions, raw_resources),
                            total=len(raw_resources),
                            desc=f"Checking resources in {sub_id[:20]}...",
                            leave=False
                        ))
                    sub_resources.extend(resource_results)

                return sub_resources

            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                results = list(tqdm(executor.map(process_subscription, subs), total=len(subs), desc="Processing Subscriptions"))

            for sub_result in results:
                resources_data.extend(sub_result)

        if self.graph_token:
            print(f"{Fore.MAGENTA}Getting Permissions from EntraID...")

            # For SPs, let's get their API permissions
            resources_data += self.EntraIDPEASS.get_api_permissions()

            # The following checks are for user principals (they use the /me endpoint)
            memberships = self.EntraIDPEASS.get_entraid_memberships()
            if memberships is not None:
                resources_data += memberships
                resources_data += self.EntraIDPEASS.get_assigned_permissions()
                resources_data += self.EntraIDPEASS.get_my_app_role_assignments()
                resources_data += self.EntraIDPEASS.get_eligible_roles()
                resources_data += self.EntraIDPEASS.get_entraid_owns()

        return resources_data
    
    def get_accesstoken_from_foci(self, client_id, scopes):
        """
        Get access token from FOCI refresh token using MSAL.
        """

        app = msal.PublicClientApplication(
                client_id=client_id, authority=f"https://login.microsoftonline.com/{self.tenant_id}"
            )
        tokens = app.acquire_token_by_refresh_token(foci_refresh_token, scopes=scopes, )
        return tokens

    def get_tokens_from_foci_with_scope(self, scope_app_ids={}):
        """
        Get a token using FOCI apps for the required resource/scopes.
        """

        for scope, app_id in scope_app_ids.items():
            token = self.get_tokens_from_foci(
                [scope],
                app_ids=app_id
            )
            if token:
                return token
        
        return None
    
    def get_tokens_from_foci(self, scopes, app_ids=[]):
        """
        Get a token using FOCI apps for the required resource/scopes.
        """

        app_ids = app_ids if app_ids else FOCI_APPS
        for app_id in app_ids:
            token = self.get_accesstoken_from_foci(
                app_id,
                scopes
            ).get("access_token")
            if token:
                return token
        
        return None


def generate_foci_token(username, password, tenant_id, scope="https://management.azure.com/.default"):
    """
    Generate a FOCI refresh token using Azure AD API via MSAL.
    
    This function authenticates using the provided username and password
    with the Azure AD application identified by client_id in the given tenant_id.
    
    It then retrieves an access token for Microsoft Management (scope: https://management.azure.com/.default).
    
    The returned token is used as the FOCI refresh token.
    """
    # Create the authority URL using the tenant id.
    authority = f"https://login.microsoftonline.com/{tenant_id}"

    if not "@" in username:
        # Service Principal Flow
        app = msal.ConfidentialClientApplication(
            username,
            client_credential=password,
            authority=authority
        )
        token_response = app.acquire_token_for_client(scopes=[scope])

        if "access_token" in token_response:
            return token_response["access_token"]
        else:
            print(f"{Fore.RED}Error acquiring token with those credentials:", token_response.get("error_description"))
            exit(1)
    
    else:
        for client_id in FOCI_APPS:
            # Initialize the MSAL PublicClientApplication with the client id and authority.
            app = msal.PublicClientApplication(client_id, authority=authority)
            
            # Acquire token using username/password flow
            try:
                token_response = app.acquire_token_by_username_password(
                    username=username,
                    password=password,
                    scopes=[scope]
                )
            except Exception as e:
                continue
        
            if "refresh_token" in token_response:
                return token_response["refresh_token"]
            
            elif "error_codes" in token_response and 50126 in token_response["error_codes"]:
                print(f"{Fore.RED}Invalid credentials given. Existing")
                exit(1)

        print(f"{Fore.RED}Error acquiring token with those credentials:", token_response.get("error_description"))
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run AzurePEASS to find all your current privileges in Azure and EntraID and check for potential privilege escalation attacks.\n"
                    "To check for Azure permissions an ARM token is needed.\n"
                    "To check for Entra ID permissions a Graph token is needed."
    )
    # Basic token and tenant parameters
    parser.add_argument('--tenant-id', help="Indicate the tenant id")
    parser.add_argument('--arm-token', help="Azure Management authentication token")
    parser.add_argument('--graph-token', help="Azure Graph authentication token")
    parser.add_argument('--foci-refresh-token', default=None, help="FOCI Refresh Token")
    parser.add_argument('--not-enumerate-m365', action="store_true", default=False, help="Don't enumerate M365 permissions")
    
    # Username and password parameters for token generation
    parser.add_argument('--username', help="Username for authentication")
    parser.add_argument('--password', help="Password for authentication")
    
    parser.add_argument('--check-only-these-subs', default="", help="In case you just want to check specific subscriptions, provide a comma-separated list of subscription IDs (e.g. 'sub1,sub2')")
    parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/azure_results.json)")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_true", default=False, help="Don't use Hacktricks AI to analyze permissions")
    
    args = parser.parse_args()
    
    tenant_id = args.tenant_id

    # Get tokens from environment variables if not supplied as arguments
    arm_token = args.arm_token or os.getenv("AZURE_ARM_TOKEN")
    graph_token = args.graph_token or os.getenv("AZURE_GRAPH_TOKEN")
    foci_refresh_token = args.foci_refresh_token

    if args.username and not args.password:
        print(f"{Fore.RED}Password is required when using username. Exiting.")
        exit(1)
    
    if args.password and not args.username:
        print(f"{Fore.RED}Username is required when using password. Exiting.")
        exit(1)
    
    if args.username and not tenant_id:
        if "@" in args.username:
            tenant_id = args.username.split("@")[-1]

    if (foci_refresh_token or args.username) and not tenant_id:
        print(f"{Fore.RED}Tenant ID is required when using FOCI refresh token or username. Exiting.")
        exit(1)

    # Automatically generate the FOCI refresh token if username and password are provided and no token exists.
    if not foci_refresh_token and args.username and args.password:
        foci_token = generate_foci_token(args.username, args.password, tenant_id)
        
        # If username, we get a FOCI refresh token
        if "@" in args.username:
            foci_refresh_token = foci_token
            print(f"{Fore.GREEN}Generated FOCI Refresh Token")
        
        # If SP, we just get an access token for management
        else:
            arm_token = foci_token
            print(f"{Fore.GREEN}Generated Management Access Token")
    
    check_only_subs = []
    if args.check_only_these_subs:
        # Split the provided subscription IDs and strip whitespace
        check_only_subs = [sub.strip() for sub in args.check_only_these_subs.split(",") if sub.strip()]
        # Check subscriptions are valid via regex
        if not all(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', sub) for sub in check_only_subs):
            print(f"{Fore.RED}Invalid subscription ID format in --check-only-these-subs. Exiting.")
            exit(1)
        
    
    # Initialize and run the AzurePEASS analysis
    azure_peass = AzurePEASS(
        arm_token,
        graph_token,
        foci_refresh_token,
        tenant_id,
        very_sensitive_combinations,  # Ensure these variables are defined in your context
        sensitive_combinations,       # Ensure these variables are defined in your context
        not_use_ht_ai=args.not_use_hacktricks_ai,
        num_threads=args.threads,
        not_enumerate_m365=args.not_enumerate_m365,
        out_path=args.out_json_path,
        check_only_subs=check_only_subs
    )
    azure_peass.run_analysis()