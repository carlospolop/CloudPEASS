import argparse
import requests
import jwt
import time
import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style, init, Back
import msal

init(autoreset=True)

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



FOCI_APPS = [
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46", # Azure CLI keep first
    "1950a258-227b-4e31-a9cf-717495945fc2",
    "cf36b471-5b44-428c-9ce7-313bf84528de",
    "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12",
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "27922004-5251-4030-b22d-91ecd9a37ea4",
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "22098786-6e16-43cc-a27d-191a01a1e3b5",
    "4813382a-8fa7-425e-ab75-3b753aab3abb",
    "4e291c71-d680-4d0e-9640-0a3358e31177",
    "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
    "57336123-6e14-4acc-8dcf-287b6088aa28",
    "66375f6b-983f-4c2c-9701-d680650f588f",
    "844cca35-0656-46ce-b636-13f48b0eecbd",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "87749df4-7ccf-48f8-aa87-704bad0e0e16",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "a569458c-7f2b-45cb-bab9-b7dee514d112",
    "af124e86-4e96-495a-b70a-90f90ab96707",
    "b26aadf8-566f-4478-926f-589f601d9c74",
    "be1918be-3fe3-4be9-b32b-b542fc27f02e",
    "cab96880-db5b-4e15-90a7-f3f1d62ffe39",
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
    "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
    "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3",
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59",
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d",
    "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "e9c51622-460d-4d3d-952d-966a5b1da34c",
    "c1c74fed-04c9-4704-80dc-9f79a2e515cb",
    "eb20f3e3-3dce-4d2c-b721-ebb8d4414067"
]


EMAIL_FOCI_APPS = { # Mails.Read
    "Mail.ReadWrite": [
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "57336123-6e14-4acc-8dcf-287b6088aa28",
        "00b41c95-dab0-4487-9791-b9d2c32c80f2"
    ],
    "Mail.Read": [
        "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
        "27922004-5251-4030-b22d-91ecd9a37ea4"
    ]
}

SHAREPOINT_FOCI_APPS = { # Sites.Read.All
    "Sites.Read.All": [
        "cf36b471-5b44-428c-9ce7-313bf84528de",
        "ab9b8c07-8f02-4f72-87fa-80105867a763",
        "af124e86-4e96-495a-b70a-90f90ab96707",
        "b26aadf8-566f-4478-926f-589f601d9c74",
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
        "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d"
    ]
}

TEAMS_FOCI_APPS = { # Team.ReadBasic.All
    "Team.ReadBasic.All": [
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    ]
}

ONEDRIVE_FOCI_APPS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
]

ONENOTE_FOCI_APPS = { # Notes.Read
    "Notes.ReadWrite.All": [
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "0ec893e0-5785-4de6-99da-4ed124e5296c",
        "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    ],
    "Notes.Create": [
        "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    ],
    "Notes.Read": [
        "57336123-6e14-4acc-8dcf-287b6088aa28"
    ]
}

CONTACTS_FOCI_APPS = { # Contacts.Read
    "Contacts.ReadWrite.Shared": [
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    ],
    "Contacts.ReadWrite": [
        "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    ],
    "Contacts.Read": [
        "57336123-6e14-4acc-8dcf-287b6088aa28",
        "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
        "00b41c95-dab0-4487-9791-b9d2c32c80f2",
        "0ec893e0-5785-4de6-99da-4ed124e5296c",
        "af124e86-4e96-495a-b70a-90f90ab96707",
        "b26aadf8-566f-4478-926f-589f601d9c74",
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
        "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d"
    ]
}

TASKS_FOCI_APPS = { # Tasks.ReadWrite (no one with Tasks.Read)
    "Tasks.ReadWrite": [
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
        "00b41c95-dab0-4487-9791-b9d2c32c80f2",
        "0ec893e0-5785-4de6-99da-4ed124e5296c"
    ],

    "Calendars.Read": [
        "57336123-6e14-4acc-8dcf-287b6088aa28",
        "af124e86-4e96-495a-b70a-90f90ab96707",
        "b26aadf8-566f-4478-926f-589f601d9c74"
    ],

    "Contacts.Read": [
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
        "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d"
    ]
}


class AzurePEASS(CloudPEASS):
    def __init__(self, arm_token, graph_token, foci_refresh_token, tenant_id, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path=None):
        self.foci_refresh_token = foci_refresh_token
        self.tenant_id = tenant_id

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
        super().__init__(very_sensitive_combos, sensitive_combos, "Azure", not_use_ht_ai, num_threads, AZURE_MALICIOUS_RESPONSE_EXAMPLE, AZURE_SENSITIVE_RESPONSE_EXAMPLE, out_path)

        if not self.arm_token and not self.graph_token:
            print(f"{Fore.RED}At lest an ARM token or Graph token is needed. Exiting.")
            exit(1)
        
        if not self.arm_token:
            print(f"{Fore.RED}ARM token not provided. Skipping Azure permissions analysis")
        
        if not self.graph_token:
            print(f"{Fore.RED}Graph token not provided. Skipping EntraID permissions analysis")

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
        url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
        resp = requests.get(url, headers={"Authorization": f"Bearer {self.arm_token}"})
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
            except Exception as e:
                print(f"{Fore.RED}Failed to decode Graph token: {str(e)}")
        
        if self.foci_refresh_token:
            
            # SHAREPOINT
            """print(f"{Fore.YELLOW}\nEnumerating SharePoint files (Thanks to JoelGMSec for the scopes):")
            sharepoint_token = self.get_tokens_from_foci(["Sites.Read.All"], SHAREPOINT_FOCI_APPS)

            if sharepoint_token:
                self.enumerate_sharepoint_files(sharepoint_token)"""
            
            
            # EMAILS
            print(f"{Fore.YELLOW}\nEnumerating Emails:")
            mail_read_token = self.get_tokens_from_foci_with_scope(EMAIL_FOCI_APPS)

            if mail_read_token:
                self.enumerate_emails(mail_read_token)
            else:
                print(f"{Fore.RED}No FOCI app with Mail.Read scope found. Skipping email enumeration.{Fore.WHITE}")

            # TEAMS
            print(f"{Fore.YELLOW}\nEnumerating Teams Conversations:")
            teams_token = self.get_tokens_from_foci_with_scope(TEAMS_FOCI_APPS)

            if teams_token:
                self.enumerate_teams_conversations(teams_token)
            else:
                print(f"{Fore.RED}No FOCI app with Teams scopes found. Skipping Teams conversations enumeration.{Fore.WHITE}")
            
            
            """# ONEDRIVE
            print(f"{Fore.YELLOW}\nEnumerating onedrive:")
            onedrive_token = self.get_tokens_from_foci(["Files.Read"], ONEDRIVE_FOCI_APPS)

            if onedrive_token:
                self.enumerate_onedrive(onedrive_token)"""
            

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

    def enumerate_sharepoint_files(self, sharepoint_token):
        headers = {'Authorization': f'Bearer {sharepoint_token}'}
        site_url = 'https://graph.microsoft.com/v1.0/sites/root/drive/root/children?$top=10'

        while site_url:
            resp = requests.get(site_url, headers=headers)
            data = resp.json()
            for item in data.get('value', []):
                print(f"{Fore.CYAN}- {item['name']} ({item['webUrl']})")

            if 'nextLink' in data:
                cont = input("Show more SharePoint files? (y/N): ")
                if cont.lower() != 'y':
                    break
                site_url = data['nextLink']
            else:
                break

    def enumerate_emails(self, outlook_token):
        headers = {'Authorization': f'Bearer {outlook_token}'}
        mail_url = 'https://graph.microsoft.com/v1.0/me/messages?$top=10'

        while mail_url:
            resp = requests.get(mail_url, headers=headers)
            data = resp.json()
            for message in data.get('value', []):
                print(f"{Fore.BLUE}Email Subject: {Fore.WHITE}{message['subject']}")
                print(f"{Fore.BLUE}From Email: {Fore.WHITE}{message['from']['emailAddress']['address']}")
                print(f"{Fore.BLUE}Snippet: {Fore.WHITE}{message['bodyPreview']}")
                print(f"{Fore.BLUE}Link: {Fore.WHITE}{message['webLink']}")
                print("-" * 50)

            if '@odata.nextLink' in data:
                cont = input("Show more Emails? (y/N): ")
                if cont.lower() != 'y':
                    break
                mail_url = data['@odata.nextLink']
            else:
                break
    
    def enumerate_teams_conversations(self, teams_token):
        headers = {'Authorization': f'Bearer {teams_token}'}
        
        # Enumerate Teams Chats
        print(f"{Fore.RED}There isn't any known FOCI app capable of giving any of the scopes: Chat.ReadBasic, Chat.Read, Chat.ReadWrite. Therefore, I cannot list chats:({Fore.WHITE}")
        """chats_url = 'https://graph.microsoft.com/v1.0/me/chats?$top=10'
        print(f"{Fore.YELLOW}\nEnumerating Teams Chats:")
        while chats_url:
            resp = requests.get(chats_url, headers=headers)
            data = resp.json()
            for chat in data.get('value', []):
                chat_type = chat.get('chatType', 'unknown')
                print(f"{Fore.CYAN}- Chat ID: {chat['id']} Type: {chat_type}")
            if '@odata.nextLink' in data:
                cont = input("Show more Teams Chats? (y/N): ")
                if cont.lower() != 'y':
                    break
                chats_url = data['@odata.nextLink']
            else:
                break"""

        # Enumerate Joined Teams (Groups)
        print(f"{Fore.GREEN}However, it's possible to enumerate the Team groups you are part of.{Fore.RESET}")
        teams_url = 'https://graph.microsoft.com/v1.0/me/joinedTeams'
        while teams_url:
            resp = requests.get(teams_url, headers=headers)
            data = resp.json()
            for team in data.get('value', []):
                print(f"{Fore.BLUE}Team: {Fore.WHITE}{team['displayName']}")
                print(f"{Fore.BLUE}Description: {Fore.WHITE}{team['description']}")
                print("-" * 50)
            if '@odata.nextLink' in data:
                cont = input("Show more Joined Teams? (y/N): ")
                if cont.lower() != 'y':
                    break
                teams_url = data['@odata.nextLink']
            else:
                break

    def enumerate_onedrive(self, onedrive_token):
        headers = {'Authorization': f'Bearer {onedrive_token}'}
        site_url = 'https://graph.microsoft.com/v1.0/sites/root/drive/root/children?$top=10'
        print(f"{Fore.YELLOW}\nListing Word and Excel files:")
        while site_url:
            resp = requests.get(site_url, headers=headers)
            data = resp.json()
            for item in data.get('value', []):
                name = item.get('name', '').lower()
                # Filter for Word and Excel file extensions
                if name.endswith(('.doc', '.docx', '.xls', '.xlsx')):
                    print(f"{Fore.CYAN}- {item['name']} ({item['webUrl']})")
            if 'nextLink' in data:
                cont = input("Show more Office files? (y/n): ")
                if cont.lower() != 'y':
                    break
                site_url = data['nextLink']
            else:
                break

    def get_resources_and_permissions(self):
        resources_data = []

        if self.arm_token:
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

        if self.graph_token:
            print(f"{Fore.MAGENTA}Getting Permissions from EntraID...")

            # If None, then it's a MI token without access to get its Entra ID permissions (probably it doesn't have them)
            ## Important: Keep this Entra ID check first
            memberships = self.EntraIDPEASS.get_entraid_memberships()
            if memberships is None:
                return resources_data
            
            resources_data += memberships
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
        tokens = app.acquire_token_by_refresh_token(foci_refresh_token, scopes=scopes)
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
    
    # Username and password parameters for token generation
    parser.add_argument('--username', help="Username for authentication")
    parser.add_argument('--password', help="Password for authentication")
    
    parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/azure_results.json)")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_false", default=False, help="Don't use Hacktricks AI to analyze permissions")
    
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
        out_path=args.out_json_path
    )
    azure_peass.run_analysis()