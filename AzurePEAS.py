import argparse
import json
import logging
import requests
import jwt
import time
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style, init, Back
import msal
import re
from urllib.parse import urlparse

init(autoreset=True)
logging.getLogger('msal').setLevel(logging.ERROR)

from src.CloudPEASS.cloudpeass import CloudPEASS, CloudResource
from src.sensitive_permissions.azure import very_sensitive_combinations, sensitive_combinations
from src.azure.entraid import EntraIDPEASS
from src.azure.arm import AzureARMEnumerator, scope_kind, scope_name
from src.azure.azcli import AzureCLIReadProbe
from src.azure.definitions import SHAREPOINT_FOCI_APPS, ONEDRIVE_FOCI_APPS, EMAIL_FOCI_APPS, TEAMS_FOCI_APPS_GRAPH, TEAMS_FOCI_APPS_SKYPE, ONENOTE_FOCI_APPS, CONTACTS_FOCI_APPS, TASKS_FOCI_APPS, FOCI_APPS

class AzurePEASS(CloudPEASS):
    def __init__(self, arm_token, graph_token, foci_refresh_token, tenant_id, very_sensitive_combos, sensitive_combos, num_threads, not_enumerate_m365, skip_entraid, out_path=None, check_only_subs=None, no_ask=False, known_scopes=None, use_az_cli=False, skip_az_cli_fallback=False, azure_services=None, debug=False):
        self.foci_refresh_token = foci_refresh_token
        self.tenant_id = tenant_id
        self.not_enumerate_m365 = not_enumerate_m365
        self.skip_entraid = skip_entraid
        self.no_ask = no_ask
        self.known_scopes = list(known_scopes or [])
        self.use_az_cli = use_az_cli
        self.skip_az_cli_fallback = skip_az_cli_fallback
        self.azure_services = list(azure_services or [])
        self.debug = debug

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
        self.graph_base = self.EntraIDPEASS.graph
        self.arm = AzureARMEnumerator(arm_token) if arm_token else None
        self.sharepoint_followed_sites_ids = []
        self.initial_subscriptions = []
        self.check_only_subs = list(check_only_subs or [])
        super().__init__(very_sensitive_combos, sensitive_combos, "Azure", num_threads, out_path)

        if not self.arm_token and not self.graph_token:
            if self.foci_refresh_token:
                print(f"{Fore.RED}It wasn't possible to generate an ARM or Graph token with that FOCI token, it's potentially malformed. Exiting..")
            else:
                print(f"{Fore.RED}At least an ARM token or Graph token is needed. Exiting.")
            exit(1)
        
        if not self.arm_token:
            print(f"{Fore.RED}ARM token not provided. Skipping Azure permissions analysis")
        
        if not self.graph_token and not self.skip_entraid:
            print(f"{Fore.YELLOW}Graph token not provided. Skipping Entra ID analysis; ARM enumeration will continue.")
        
        if self.skip_entraid:
            print(f"{Fore.YELLOW}Skipping EntraID enumeration (--skip-entraid flag set)")

        if self.arm_token:
            self.check_jwt_token(self.arm_token, [
                "https://management.azure.com/",
                "https://management.core.windows.net/",
                "https://management.usgovcloudapi.net/",
                "https://management.core.usgovcloudapi.net/",
                "https://management.chinacloudapi.cn/",
                "https://management.core.chinacloudapi.cn/",
                "https://management.microsoftazure.de/",
                "https://management.core.cloudapi.de/",
            ])

        if self.graph_token and not self.skip_entraid:
            self.check_jwt_token(self.graph_token, [
                "https://graph.microsoft.com/",
                "00000003-0000-0000-c000-000000000000",
                "https://graph.microsoft.us/",
                "https://dod-graph.microsoft.us/",
                "https://microsoftgraph.chinacloudapi.cn/",
            ])

        if self.arm_token and self.graph_token and not self.skip_entraid:
            arm_claims = self._decode_claims(self.arm_token)
            graph_claims = self._decode_claims(self.graph_token)
            mismatches = [
                claim
                for claim in ("tid", "oid")
                if arm_claims.get(claim)
                and graph_claims.get(claim)
                and arm_claims[claim] != graph_claims[claim]
            ]
            if mismatches:
                print(
                    f"{Fore.RED}[!] ARM and Graph tokens have different {', '.join(mismatches)} claims. "
                    "Results describe different identities and must not be treated as one principal."
                )

    
    def check_jwt_token(self, token, expected_audiences):
        try:
            # Decode the token without verifying the signature
            decoded = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})

            # Azure emits equivalent URI audiences with and without a trailing
            # slash depending on token version and cloud.
            audience = str(decoded.get("aud") or "").rstrip("/").casefold()
            normalized_expected = {
                str(value).rstrip("/").casefold() for value in expected_audiences
            }
            if audience not in normalized_expected:
                raise ValueError(f"Invalid audience. Expected '{expected_audiences}', got '{decoded.get('aud')}'")

            # Check if token has expired
            current_time = int(time.time() + 30) # Extra 30 secs to account for clock skew
            if decoded.get("exp", 0) < current_time:
                raise ValueError(f"Token {decoded.get('exp')} has expired")

            return True

        except jwt.DecodeError:
            raise ValueError("Token is invalid or badly formatted")

    def _graph_get_json(self, url, headers, label="Graph API"):
        """Return a Graph JSON object or an empty object without aborting the run."""
        try:
            response = self.EntraIDPEASS.http.get(url, headers=headers)
        except Exception as exc:
            print(f"{Fore.YELLOW}[!] {label} request failed: {str(exc)[:300]}")
            return {}
        if response.status_code != 200:
            print(
                f"{Fore.YELLOW}[!] {label} unavailable ({response.status_code}): "
                f"{self.EntraIDPEASS._error_text(response)}"
            )
            return {}
        try:
            return response.json()
        except ValueError:
            print(f"{Fore.YELLOW}[!] {label} returned a non-JSON response.")
            return {}

    @staticmethod
    def _next_graph_url(data, current_url, seen_urls, label, max_pages=100):
        """Return a safe next link while bounding malformed Graph pagination."""
        next_url = data.get('@odata.nextLink') or data.get('nextLink')
        if not next_url:
            return None
        if next_url == current_url or next_url in seen_urls:
            print(f"{Fore.YELLOW}[!] {label} pagination loop detected; stopping.")
            return None
        if len(seen_urls) >= max_pages:
            print(f"{Fore.YELLOW}[!] {label} exceeded {max_pages} pages; stopping.")
            return None
        seen_urls.add(next_url)
        return next_url


    def list_subscriptions(self):
        if self.check_only_subs:
            # If check_only_subs is provided, return only those subscriptions
            return self.check_only_subs
        
        subscriptions, status, error = self.arm.list_subscriptions()
        if status != 200:
            print(f"{Fore.YELLOW}[!] Subscription discovery failed ({status}): {error}")
            print(f"{Fore.CYAN}    Fallback: pass known IDs with --check-only-these-subs.")
        subs = [sub.get("subscriptionId") for sub in subscriptions if sub.get("subscriptionId")]
        for sub in self.initial_subscriptions:
            if sub not in subs:
                subs.append(sub)
        return subs

    def list_resources_in_subscription(self, subscription_id):
        resources, status, error = self.arm.list_resources(subscription_id)
        if status != 200 and self.debug:
            print(f"{Fore.YELLOW}[debug] Resource discovery failed for {subscription_id}: {status} {error}")
        return resources

    def get_permissions_for_resource(self, resource_id, cont=0):
        """Compatibility wrapper returning active effective permissions only."""
        return self.arm.get_effective_permissions(resource_id).allowed
    
    def print_whoami_info(self):
        """
        Prints the current principal information.
        This is useful for debugging and understanding the context of the permissions being analyzed.
        """
        whoami = {
            "cloud": "azure",
            "tenant_id": self.tenant_id,
            "arm": {},
            "graph": {},
        }

        if self.arm_token:
            try:
                # Get also email and groups
                decoded = jwt.decode(self.arm_token, options={"verify_signature": False, "verify_aud": False})
                whoami["tenant_id"] = whoami["tenant_id"] or decoded.get("tid")
                whoami["arm"] = {
                    "oid": decoded.get("oid"),
                    "aud": decoded.get("aud"),
                    "upn": decoded.get("upn"),
                    "email": decoded.get("email"),
                    "appid": decoded.get("appid"),
                    "scp": decoded.get("scp"),
                    "roles": decoded.get("roles"),
                    "idtyp": decoded.get("idtyp"),
                    "xms_mirid": decoded.get("xms_mirid"),
                }
                print(f"{Fore.BLUE}Current Principal ID (ARM Token): {Fore.WHITE}{decoded.get('oid', 'Unknown')}")
                principal_type = "application/managed identity" if decoded.get("idtyp") == "app" or (decoded.get("appid") and not decoded.get("upn")) else "user"
                print(f"{Fore.BLUE}Principal Type (ARM Token): {Fore.WHITE}{principal_type}")
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
                managed_identity_resource = decoded.get("xms_mirid")
                if managed_identity_resource and managed_identity_resource not in self.known_scopes:
                    self.known_scopes.append(managed_identity_resource)
                    print(f"{Fore.BLUE}Managed Identity Resource: {Fore.WHITE}{managed_identity_resource}")
                if self.initial_subscriptions:
                    print(f"{Fore.BLUE}Initial Subscriptions: {Fore.WHITE}{', '.join(self.initial_subscriptions)}")
                print()
            except Exception as e:
                print(f"{Fore.RED}Failed to decode ARM token: {str(e)}")
        
        if self.graph_token and not self.skip_entraid:
            try:
                # Decode the Graph token to get the current principal information
                decoded = jwt.decode(self.graph_token, options={"verify_signature": False, "verify_aud": False})
                whoami["tenant_id"] = whoami["tenant_id"] or decoded.get("tid")
                whoami["graph"] = {
                    "oid": decoded.get("oid"),
                    "aud": decoded.get("aud"),
                    "upn": decoded.get("upn"),
                    "email": decoded.get("email"),
                    "appid": decoded.get("appid"),
                    "scp": decoded.get("scp"),
                    "roles": decoded.get("roles"),
                    "wids": decoded.get("wids"),
                    "idtyp": decoded.get("idtyp"),
                }
                print(f"{Fore.BLUE}Current Principal ID (Graph Token): {Fore.WHITE}{decoded.get('oid', 'Unknown')}")
                principal_type = "application" if decoded.get("idtyp") == "app" or (decoded.get("appid") and not decoded.get("scp")) else "user"
                print(f"{Fore.BLUE}Principal Type (Graph Token): {Fore.WHITE}{principal_type}")
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
        
        if self.foci_refresh_token and not self.not_enumerate_m365 and not self.skip_entraid:
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

        return whoami


    def enumerate_conditional_access_policies(self, graph_token):
        """
        List all Conditional Access policies via Microsoft Graph.
        """

        headers = {'Authorization': f'Bearer {graph_token}'}
        url = f'{self.graph_base}/v1.0/identity/conditionalAccess/policies'
        seen_urls = {url}
        while url:
            data = self._graph_get_json(url, headers, "Conditional Access policies")
            if not data:
                break
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
            url = self._next_graph_url(data, url, seen_urls, "Conditional Access policies")

    
    def enumerate_tasks(self, tasks_token):
        headers = {'Authorization': f'Bearer {tasks_token}'}
        lists_url = f'{self.graph_base}/v1.0/me/todo/lists?$top=10'
        seen_urls = {lists_url}

        while lists_url:
            data = self._graph_get_json(lists_url, headers, "To-Do lists")
            if not data:
                break
            
            for todo_list in data.get('value', []):
                list_id = todo_list.get('id')
                print(f"{Fore.BLUE}- List: {Fore.WHITE}{todo_list.get('displayName', 'Unnamed')}")
                if not list_id:
                    continue
                # Enumerate tasks within the current To-Do list
                tasks_url = f"{self.graph_base}/v1.0/me/todo/lists/{list_id}/tasks?$top=10"
                tasks_data = self._graph_get_json(tasks_url, headers, "To-Do tasks")
                
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
                if self.no_ask:
                    cont = 'n'
                else:
                    cont = input("Show more To-Do lists? (y/n): ")
                if cont.lower() != 'y':
                    break
                lists_url = self._next_graph_url(data, lists_url, seen_urls, "To-Do lists")
            else:
                break
    
    def enumerate_contacts(self, contacts_token):
        headers = {'Authorization': f'Bearer {contacts_token}'}
        contacts_url = f'{self.graph_base}/v1.0/me/contacts?$top=10'
        seen_urls = {contacts_url}
        
        while contacts_url:
            data = self._graph_get_json(contacts_url, headers, "Contacts")
            if not data:
                break
            
            for contact in data.get('value', []):
                name = contact.get('displayName', contact.get('givenName', 'No Name'))
                phones = sorted(
                    {
                        phone
                        for phone in (
                            (contact.get('homePhones') or [])
                            + [contact.get('mobilePhone')]
                            + (contact.get('businessPhones') or [])
                        )
                        if phone
                    }
                )
                emails = contact.get('emailAddresses', [])
                print(f"{Fore.BLUE}Name: {Fore.WHITE}{str(name)}")
                print(f"{Fore.BLUE}Phones: {Fore.WHITE}{str(phones)}")
                print(f"{Fore.BLUE}Emails: {Fore.WHITE}{str(emails)}")
                print("-" * 50)
            
            # Handle pagination if there's more data
            if '@odata.nextLink' in data:
                if self.no_ask:
                    cont = 'n'
                else:
                    cont = input("Show more Contacts? (y/N): ")
                if cont.lower() != 'y':
                    break
                contacts_url = self._next_graph_url(data, contacts_url, seen_urls, "Contacts")
            else:
                break
    
    def enumerate_onenote_content(self, onenote_token):
        headers = {'Authorization': f'Bearer {onenote_token}'}
        notebooks_url = f'{self.graph_base}/v1.0/me/onenote/notebooks?$top=10'
        seen_urls = {notebooks_url}
        
        # Loop through notebooks pages if paginated
        while notebooks_url:
            data = self._graph_get_json(notebooks_url, headers, "OneNote notebooks")
            if not data:
                break
            
            for notebook in data.get('value', []):
                notebook_id = notebook.get('id')
                print(f"{Fore.BLUE}Notebook: {Fore.WHITE}{notebook.get('displayName', 'Unnamed')}")
                print(f"{Fore.BLUE}Role: {Fore.WHITE}{notebook.get('userRole', 'Unknown')}")
                print(f"{Fore.BLUE}Is Shared?: {Fore.WHITE}{notebook.get('isShared', 'Unknown')}")
                print(f"{Fore.BLUE}Last Modified: {Fore.WHITE}{notebook.get('lastModifiedDateTime', 'Unknown')}")
                creator = (
                    notebook.get('createdBy', {}).get('user', {}).get('displayName')
                    or notebook.get('createdBy', {}).get('application', {}).get('displayName')
                    or 'Unknown'
                )
                print(f"{Fore.BLUE}Created by: {Fore.WHITE}{creator}")
                print("-" * 50)
                
                # Enumerate Sections within each Notebook
                sections_data = {}
                if notebook_id:
                    sections_url = f"{self.graph_base}/v1.0/me/onenote/notebooks/{notebook_id}/sections"
                    sections_data = self._graph_get_json(sections_url, headers, "OneNote sections")
                
                for section in sections_data.get('value', []):
                    print(
                        f"    {Fore.BLUE}- Section: {section.get('displayName', 'Unnamed')} "
                        f"(ID: {section.get('id', 'Unknown')})"
                    )
            
            # Check if there's more data to paginate
            if '@odata.nextLink' in data:
                if self.no_ask:
                    cont = 'n'
                else:
                    cont = input("Show more OneNote Notebooks? (y/N): ")
                if cont.lower() != 'y':
                    break
                notebooks_url = self._next_graph_url(
                    data, notebooks_url, seen_urls, "OneNote notebooks"
                )
            else:
                break

    def fetch_paginated_data(self, url, token):
        """Helper to retrieve all paginated data from a Graph API endpoint."""
        headers = {'Authorization': f'Bearer {token}'}
        items = []
        seen_urls = {url}
        while url:
            data = self._graph_get_json(url, headers, "Paginated Graph data")
            if not data:
                break
            items.extend(data.get("value", []))
            url = self._next_graph_url(data, url, seen_urls, "Paginated Graph data")
        return items


    def enumerate_site(self, site, token, indent=""):
        """Print details of a single site and enumerate its documents."""
        name = site.get("displayName") or site.get("name", "Unnamed")
        web_url = site.get("webUrl", "No URL provided")
        site_id = site.get("id")
        print(f"{indent}- {Fore.YELLOW}Site:{Fore.RESET} {name} | {Fore.BLUE}{web_url}")
        if site_id:
            self.sharepoint_list_documents(site_id, token, indent + "  ")

    def sharepoint_enumerate_followed_sites(self, token, depth=1, max_depth=3, url=None):
        """Recursively enumerate followed sites."""

        url = url or f"{self.graph_base}/v1.0/me/followedSites"

        if depth == 1:
            print(f"\n{Fore.CYAN}Followed Sites:{Fore.RESET}")
        headers = {'Authorization': f'Bearer {token}'}
        indent = "  " * (depth - 1)
        seen_urls = {url}
        
        while url:
            data = self._graph_get_json(url, headers, "SharePoint followed sites")
            if not data:
                break
            for site in data.get("value", []):
                if site.get("id"):
                    self.sharepoint_followed_sites_ids.append(site["id"])
                self.enumerate_site(site, token, indent)
                if depth < max_depth and site.get("id"):
                    subsites_url = f"{self.graph_base}/v1.0/sites/{site.get('id')}/sites?$top=10"
                    self.sharepoint_enumerate_followed_sites(token, depth + 1, max_depth, subsites_url)
            url = self._next_graph_url(data, url, seen_urls, "SharePoint followed sites")

    def sharepoint_list_documents(self, site_id, token, indent="", depth=1, max_depth=3):
        """List documents in the default document library of a site."""
        headers = {'Authorization': f'Bearer {token}'}
        url = f"{self.graph_base}/v1.0/sites/{site_id}/drive/root/children?$top=10"
        print(f"{indent}Documents:")
        seen_urls = {url}
        while url:
            data = self._graph_get_json(url, headers, "SharePoint documents")
            if not data:
                break
            for item in data.get("value", []):
                item_name = item.get("name", "Unnamed item")
                if "folder" in item:
                    print(f"{indent}  - {Fore.MAGENTA}Folder: {Fore.RESET}{item_name}")
                    if depth < max_depth:
                        self.sharepoint_list_folder_contents(
                            site_id,
                            token,
                            item.get("id"),
                            indent + "    ",
                            depth=depth + 1,
                            max_depth=max_depth,
                        )
                else:
                    size = item.get("size", "Unknown")
                    last_modified = item.get("lastModifiedDateTime", "Unknown")
                    print(f"{indent}- {Fore.GREEN}File: {Fore.RESET}{item_name} | {Fore.CYAN}Size:{Fore.RESET} {size} bytes | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}")
            url = self._next_graph_url(data, url, seen_urls, "SharePoint documents")

    def sharepoint_list_folder_contents(
        self, site_id, token, folder_id, indent="", depth=2, max_depth=3
    ):
        """Recursively list folder contents."""
        if not folder_id or depth > max_depth:
            return
        headers = {'Authorization': f'Bearer {token}'}
        url = f"{self.graph_base}/v1.0/sites/{site_id}/drive/items/{folder_id}/children?$top=10"
        seen_urls = {url}
        while url:
            data = self._graph_get_json(url, headers, "SharePoint folder contents")
            if not data:
                break
            for item in data.get("value", []):
                item_name = item.get("name", "Unnamed item")
                if "folder" in item:
                    print(f"{indent}- {Fore.BLUE}Folder: {Fore.RESET}{item_name}")
                    if depth < max_depth:
                        self.sharepoint_list_folder_contents(
                            site_id,
                            token,
                            item.get("id"),
                            indent + "  ",
                            depth=depth + 1,
                            max_depth=max_depth,
                        )
                else:
                    size = item.get("size", "Unknown")
                    last_modified = item.get("lastModifiedDateTime", "Unknown")
                    print(f"{indent}- {Fore.GREEN}File: {Fore.RESET}{item_name} | {Fore.CYAN}Size:{Fore.RESET} {size} bytes | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}")
            url = self._next_graph_url(data, url, seen_urls, "SharePoint folders")

    def sharepoint_enumerate_public_sites(self, token):
        """Enumerate public sites not already followed by the current user."""
        url = f"{self.graph_base}/v1.0/sites?search=*"
        print(f"\n{Fore.CYAN}Public Sites:{Fore.RESET}")
        seen_urls = {url}
        while url:
            data = self._graph_get_json(url, {'Authorization': f'Bearer {token}'}, "SharePoint public sites")
            if not data:
                break
            for site in data.get("value", []):
                if site.get("id") in self.sharepoint_followed_sites_ids:
                    continue
                self.enumerate_site(site, token, indent="")  # No extra indentation for public sites
            url = self._next_graph_url(data, url, seen_urls, "SharePoint public sites")

    def enumerate_emails(self, outlook_token):
        headers = {'Authorization': f'Bearer {outlook_token}'}
        mail_url = f'{self.graph_base}/v1.0/me/messages?$top=10'
        seen_urls = {mail_url}

        while mail_url:
            data = self._graph_get_json(mail_url, headers, "Mail")
            if not data:
                break
            
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
                if self.no_ask:
                    cont = 'n'
                else:
                    cont = input("Show more Emails? (y/N): ")
                if cont.lower() != 'y':
                    break
                mail_url = self._next_graph_url(data, mail_url, seen_urls, "Mail")
            else:
                break
    
    def enumerate_teams_conversations(self, teams_token_skype, teams_token_graph):
        # Get Skype token
        if not teams_token_skype:
            print(f"{Fore.RED}No FOCI app with Skype scopes found. Skipping conversations enumeration.{Fore.WHITE}")
            
        else:
            headers = {'Authorization': f'Bearer {teams_token_skype}'}
            url = "https://teams.microsoft.com/api/authsvc/v1.0/authz"
            try:
                resp = requests.post(url, headers=headers, timeout=(10, 45))
                data = resp.json() if resp.status_code == 200 else {}
            except (requests.RequestException, ValueError) as exc:
                print(f"{Fore.YELLOW}[!] Teams token exchange failed: {str(exc)[:300]}")
                data = {}
            skype_token = data.get("tokens", {}).get("skypeToken")
            chat_service_uri = data.get("regionGtms", {}).get("chatService")

            if not chat_service_uri:
                print(f"{Fore.RED}No access to chats.")
            else:
                parsed_chat_uri = urlparse(chat_service_uri)
                chat_host = (parsed_chat_uri.hostname or "").lower()
                if parsed_chat_uri.scheme != "https" or not (
                    chat_host == "teams.microsoft.com"
                    or chat_host.endswith(".teams.microsoft.com")
                    or chat_host.endswith(".skype.com")
                ):
                    print(f"{Fore.RED}[!] Refusing unexpected Teams chat endpoint: {chat_host or 'invalid URL'}")
                else:
                    # Get open conversations
                    headers = {
                        "Authentication": f"skypetoken={skype_token}",
                        'Authorization': f'Bearer {teams_token_skype}',
                    }
                    url = f"{chat_service_uri.rstrip('/')}/v1/users/ME/conversations?view=msnp24Equivalent&pageSize=500"
                    try:
                        resp = requests.get(
                            url,
                            headers=headers,
                            timeout=(10, 45),
                            allow_redirects=False,
                        )
                        data = resp.json() if resp.status_code == 200 else {}
                    except (requests.RequestException, ValueError) as exc:
                        print(f"{Fore.YELLOW}[!] Teams conversations read failed: {str(exc)[:300]}")
                        data = {}

                    if not data.get("conversations"):
                        print(f"{Fore.GREEN}No conversations found in Teams.{Fore.WHITE}")
                    else:
                        print(f"{Fore.GREEN}Some conversations found in Teams:{Fore.WHITE}")
                        for conversation in data.get("conversations", []):
                            conv_id = conversation.get("id")
                            conv_role = conversation.get("memberProperties", {}).get("role")
                            conv_type = conversation.get("type")
                            last_message = conversation.get("lastMessage") or {}
                            last_message_content = last_message.get("content", "")
                            last_message_from = (
                                last_message.get("fromDisplayNameInToken")
                                or last_message.get("imdisplayname")
                                or "Unknown"
                            )

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
            teams_url = f'{self.graph_base}/v1.0/me/joinedTeams'
            seen_urls = {teams_url}
            while teams_url:
                data = self._graph_get_json(teams_url, headers, "Joined Teams")
                if not data:
                    break
                if data.get('value', []):
                    print(f"{Fore.GREEN}Some teams found in Teams:{Fore.WHITE}")
                    for team in data.get('value', []):
                        print(f"{Fore.BLUE}  Team: {Fore.WHITE}{team.get('displayName', 'Unnamed')}")
                        print(f"{Fore.BLUE}  Description: {Fore.WHITE}{team.get('description') or 'None'}")
                        print()
                    if '@odata.nextLink' in data:
                        if self.no_ask:
                            cont = 'n'
                        else:
                            cont = input("Show more Joined Teams? (y/N): ")
                        if cont.lower() != 'y':
                            break
                        teams_url = self._next_graph_url(
                            data, teams_url, seen_urls, "Joined Teams"
                        )
                    else:
                        break
                
                else:
                    print(f"{Fore.GREEN}No teams found in Teams.{Fore.WHITE}")
                    break

    def enumerate_onedrive(self, onedrive_token, max_depth=3):
        # Root URL to list items in the root folder
        root_url = f"{self.graph_base}/v1.0/me/drive/root/children?$top=10"
        self._list_items(root_url, onedrive_token, depth=1, max_depth=max_depth)

    def _list_items(self, url, token, depth, max_depth):
        headers = {'Authorization': f'Bearer {token}'}
        # Indentation for hierarchical display
        indent = "  " * (depth - 1)
        seen_urls = {url}
        while url:
            data = self._graph_get_json(url, headers, "OneDrive items")
            if not data:
                break
            for item in data.get('value', []):
                name = item.get('name', 'Unnamed')
                last_modified = item.get('lastModifiedDateTime', 'Unknown')
                web_url = item.get('webUrl', 'Unknown')
                # Determine the type of the item
                folder = item.get('folder')
                if isinstance(folder, dict):
                    special_folder = (folder.get('specialFolder') or {}).get('name', '')
                    if special_folder:
                        msg = f"{indent}- {Fore.MAGENTA}Folder: {Fore.RESET}{name} | {Fore.CYAN}Special folder:{Fore.RESET} {special_folder} | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}"
                    else:
                        msg = f"{indent}- {Fore.MAGENTA}Folder: {Fore.RESET}{name} | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}"
                    print(msg)
                    
                    # Recursive call for folder contents if max_depth is not reached
                    if depth < max_depth and item.get('id'):
                        folder_children_url = f"{self.graph_base}/v1.0/me/drive/items/{item['id']}/children?$top=50"
                        self._list_items(folder_children_url, token, depth + 1, max_depth)
                
                else:
                    size = item.get('size', 'Unknown')
                    print(f"{indent}- {Fore.GREEN}File: {Fore.RESET}{name} | {Fore.CYAN}Size: {Fore.RESET}{size} | {Fore.CYAN}Last Modified:{Fore.RESET} {last_modified}")
            
            # Handle pagination: continue if a next page exists
            url = self._next_graph_url(data, url, seen_urls, "OneDrive items")

    @staticmethod
    def _decode_claims(token):
        if not token:
            return {}
        try:
            return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        except Exception:
            return {}

    @staticmethod
    def _subscription_from_scope(scope):
        match = re.match(r"^/subscriptions/([0-9a-fA-F-]{36})(?:/|$)", scope or "", re.I)
        return match.group(1) if match else None

    @staticmethod
    def _scope_resource(scope, permissions, excluded=None, **extra):
        return CloudResource(
            resource_id=scope,
            name=extra.pop("name", scope_name(scope)),
            resource_type=extra.pop("resource_type", scope_kind(scope)),
            permissions=permissions,
            deny_perms=excluded or [],
            is_admin=extra.pop("is_admin", False),
            **extra,
        )

    def _role_assignment_resource(self, assignment, assignment_type="Assigned"):
        properties = assignment.get("properties", {})
        role_definition_id = properties.get("roleDefinitionId")
        result = self.arm.permissions_for_role(role_definition_id)
        if not result.succeeded:
            return None
        role = self.arm.get_role_definition(role_definition_id) or {}
        role_name = role.get("properties", {}).get("roleName") or role_definition_id
        condition = properties.get("condition")
        if condition:
            role_name = f"{role_name} (conditional assignment)"
        scope = properties.get("scope") or assignment.get("id") or "unknown-scope"
        resource_id = scope
        if assignment_type.lower() == "eligible":
            resource_id = f"{scope}#eligible-role:{role_definition_id.rsplit('/', 1)[-1]}"
        elif condition:
            assignment_id = (assignment.get("name") or assignment.get("id") or "conditional").rsplit("/", 1)[-1]
            resource_id = f"{scope}#conditional-role-assignment:{assignment_id}"
        return self._scope_resource(
            resource_id,
            result.allowed,
            result.excluded,
            name=role_name,
            assignmentType=assignment_type,
            condition=condition,
            conditionVersion=properties.get("conditionVersion"),
        )

    def _run_cli_fallback(self, subscription_id):
        if not self.use_az_cli or self.skip_az_cli_fallback:
            return []
        print(
            f"{Fore.CYAN}[i] ARM permission APIs returned no permissions for {subscription_id}. "
            "Trying safe read-only Azure CLI commands as a fallback."
        )
        probe = AzureCLIReadProbe(
            subscription_id,
            services=self.azure_services,
            threads=self.num_threads,
            debug=self.debug,
        )
        if not probe.executable:
            print(f"{Fore.YELLOW}[!] Azure CLI is not installed; skipping CLI fallback.")
            return []
        commands = probe.discover_commands()
        if not commands:
            print(f"{Fore.YELLOW}[!] No safe Azure CLI read commands were discovered.")
            return []

        found = []
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {executor.submit(probe.probe, command): command for command in commands}
            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Read-only Azure CLI fallback",
                leave=False,
            ):
                result = future.result()
                if result.succeeded:
                    command_text = "az " + " ".join(result.command)
                    found.append(
                        CloudResource(
                            resource_id=f"/subscriptions/{subscription_id}/providers/CloudPEASS/cliRead/{'-'.join(result.command)}",
                            name=command_text,
                            resource_type="read-only-cli-evidence",
                            permissions=[result.permission_label],
                            deny_perms=[],
                            evidence=result.status,
                        )
                    )
                    print(f"{Fore.GREEN}[+] Read access confirmed: {Fore.WHITE}{command_text}")
                elif self.debug and result.detail:
                    print(f"{Fore.YELLOW}[debug] {' '.join(result.command)}: {result.status}: {result.detail}")
        print(f"{Fore.CYAN}[i] CLI fallback confirmed {len(found)} read commands.")
        return found

    def get_resources_and_permissions(self):
        resources_data = []

        if self.arm_token:
            print(
                f"{Fore.CYAN}[i] A permission prefixed with '-' is an Azure role NotAction/"
                "NotDataAction exclusion, not a deny assignment."
            )
            arm_claims = self._decode_claims(self.arm_token)
            principal_id = arm_claims.get("oid")
            management_groups, mg_status, mg_error = self.arm.list_management_groups()
            mg_scopes = {
                item.get("id"): item
                for item in management_groups
                if item.get("id")
            }
            for scope in self.known_scopes:
                if scope.lower().startswith("/providers/microsoft.management/managementgroups/"):
                    mg_scopes.setdefault(scope, {"id": scope, "name": scope_name(scope)})
            for mg_scope, metadata in mg_scopes.items():
                result = self.arm.get_effective_permissions(mg_scope)
                if result.allowed or result.excluded:
                    resources_data.append(
                        self._scope_resource(
                            mg_scope,
                            result.allowed,
                            result.excluded,
                            name=metadata.get("name") or scope_name(mg_scope),
                            resource_type="management_group",
                            is_admin=self._is_admin_azure(result.allowed),
                            evidence="effective-permissions-api",
                        )
                    )
                if principal_id:
                    assignments, status, error = self.arm.list_assignments_for_principal(mg_scope, principal_id)
                    if status == 200:
                        for assignment in assignments:
                            resource = self._role_assignment_resource(assignment)
                            if resource:
                                resources_data.append(resource)
            if mg_status == 200 and management_groups:
                resources_data.append(
                    CloudResource(
                        resource_id="#azure:management-groups",
                        name="Management groups visible to the principal",
                        resource_type="management_group_discovery",
                        permissions=["Microsoft.Management/managementGroups/read"],
                        deny_perms=[],
                        evidence="successful-read-only-api-call",
                    )
                )
            elif self.debug:
                print(f"{Fore.YELLOW}[debug] Management group discovery unavailable: {mg_error}")
            if self.check_only_subs:
                subs = list(self.check_only_subs)
                subscription_list_status = None
            else:
                subscriptions, subscription_list_status, error = self.arm.list_subscriptions()
                subs = [
                    sub.get("subscriptionId")
                    for sub in subscriptions
                    if sub.get("subscriptionId")
                ]
                if subscription_list_status != 200:
                    print(f"{Fore.YELLOW}[!] Could not list subscriptions: {error}")
                    print(f"{Fore.CYAN}    Fallback: use --check-only-these-subs with any known subscription IDs.")

            for sub_id in self.initial_subscriptions:
                if sub_id not in subs:
                    subs.append(sub_id)
            for scope in self.known_scopes:
                sub_id = self._subscription_from_scope(scope)
                if sub_id and sub_id not in subs:
                    subs.append(sub_id)

            if not subs:
                print(f"{Fore.YELLOW}[!] No subscriptions were discovered.")
                print(f"{Fore.CYAN}    Token-only identity information is still shown above.")
                print(f"{Fore.CYAN}    Fallback: supply --check-only-these-subs or --scopes with known ARM IDs.")

            for sub_id in tqdm(subs, desc="Processing subscriptions"):
                sub_resources = []
                sub_scope = f"/subscriptions/{sub_id}"
                resource_groups, rg_status, rg_error = self.arm.list_resource_groups(sub_id)
                raw_resources, resource_status, resource_error = self.arm.list_resources(sub_id)
                if rg_status != 200:
                    print(f"{Fore.YELLOW}[!] Resource groups not listable in {sub_id}; continuing with known scopes.")
                if resource_status != 200:
                    print(f"{Fore.YELLOW}[!] Resources not listable in {sub_id}; direct-scope checks still run.")
                    if self.debug:
                        print(f"{Fore.YELLOW}[debug] {resource_error or rg_error}")

                scope_metadata = {
                    sub_scope.lower(): {"id": sub_scope, "name": sub_id, "type": "subscription"}
                }
                for group in resource_groups:
                    if group.get("id"):
                        scope_metadata[group["id"].lower()] = group
                for resource in raw_resources:
                    if resource.get("id"):
                        scope_metadata[resource["id"].lower()] = resource
                for scope in self.known_scopes:
                    if self._subscription_from_scope(scope) == sub_id:
                        scope_metadata.setdefault(scope.lower(), {"id": scope})

                permission_success = False
                with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                    futures = {
                        executor.submit(self.arm.get_effective_permissions, metadata["id"]): metadata
                        for metadata in scope_metadata.values()
                    }
                    for future in tqdm(
                        as_completed(futures),
                        total=len(futures),
                        desc=f"Effective permissions {sub_id[:8]}",
                        leave=False,
                    ):
                        metadata = futures[future]
                        result = future.result()
                        if result.succeeded:
                            permission_success = permission_success or bool(result.allowed or result.excluded)
                            if result.allowed or result.excluded:
                                is_admin = self._is_admin_azure(result.allowed)
                                sub_resources.append(
                                    self._scope_resource(
                                        metadata["id"],
                                        result.allowed,
                                        result.excluded,
                                        name=metadata.get("name") or scope_name(metadata["id"]),
                                        resource_type=metadata.get("type") or scope_kind(metadata["id"]),
                                        is_admin=is_admin,
                                        evidence="effective-permissions-api",
                                    )
                                )
                                if is_admin and metadata["id"].lower() == sub_scope.lower():
                                    print(f"{Fore.RED}{Back.YELLOW} ADMIN-LIKE ARM ACCESS: {sub_id} {Style.RESET_ALL}")
                        elif self.debug:
                            print(f"{Fore.YELLOW}[debug] Permissions unavailable for {metadata['id']}: {result.status_code} {result.error}")

                observed = []
                if subscription_list_status == 200:
                    observed.append("Microsoft.Resources/subscriptions/read")
                if rg_status == 200:
                    observed.append("Microsoft.Resources/subscriptions/resourceGroups/read")
                if resource_status == 200:
                    observed.append("Microsoft.Resources/subscriptions/resources/read")
                if observed:
                    sub_resources.append(
                        self._scope_resource(
                            sub_scope,
                            observed,
                            name=f"{sub_id} (confirmed read API calls)",
                            evidence="successful-read-only-api-call",
                        )
                    )

                if principal_id:
                    assignments, assignment_status, assignment_error = self.arm.list_assignments_for_principal(sub_scope, principal_id)
                    if assignment_status == 200:
                        for assignment in assignments:
                            resource = self._role_assignment_resource(assignment)
                            if resource:
                                sub_resources.append(resource)
                    elif self.debug:
                        print(f"{Fore.YELLOW}[debug] IAM assignment fallback unavailable: {assignment_error}")

                eligible, eligible_status, eligible_error = self.arm.list_eligible_assignments(sub_scope)
                if eligible_status == 200:
                    for assignment in eligible:
                        resource = self._role_assignment_resource(assignment, "Eligible")
                        if resource:
                            sub_resources.append(resource)
                elif self.debug:
                    print(f"{Fore.YELLOW}[debug] PIM eligibility unavailable: {eligible_error}")

                if not permission_success:
                    sub_resources.extend(self._run_cli_fallback(sub_id))
                resources_data.extend(sub_resources)

        if self.graph_token and not self.skip_entraid:
            print(f"{Fore.MAGENTA}Getting Permissions from EntraID...")

            # For SPs, let's get their API permissions
            resources_data += self.EntraIDPEASS.get_api_permissions()

            # The following checks are for user principals (they use the /me endpoint)
            memberships = self.EntraIDPEASS.get_entraid_memberships()
            if memberships is not None:
                # User principal - use existing /me endpoint methods
                resources_data += memberships
                resources_data += self.EntraIDPEASS.get_assigned_permissions()
                resources_data += self.EntraIDPEASS.get_my_app_role_assignments()
                resources_data += self.EntraIDPEASS.get_eligible_roles()
                resources_data += self.EntraIDPEASS.get_entraid_owns()
            else:
                # Service Principal or Managed Identity - use SP-specific methods
                sp_id = self.EntraIDPEASS.get_sp_principal_id()
                if sp_id:
                    print(f"{Fore.CYAN}Checking independent Entra fallbacks for this application identity...{Style.RESET_ALL}")
                    # Never gate all methods on one permission check: each endpoint has
                    # different least-privileged access requirements.
                    resources_data += self.EntraIDPEASS.get_sp_directory_role_assignments(sp_id)
                    resources_data += self.EntraIDPEASS.get_sp_group_memberships(sp_id)
                    resources_data += self.EntraIDPEASS.get_sp_app_role_assignments(sp_id)
                    resources_data += self.EntraIDPEASS.get_sp_eligible_roles(sp_id)
                    resources_data += self.EntraIDPEASS.get_sp_owned_objects(sp_id)

        return resources_data
    
    def _is_admin_azure(self, permissions):
        """
        Check if the permissions indicate admin/owner access in Azure.
        Returns True if user has Owner-like access.
        """
        perms_str = [str(p).lower() for p in permissions]
        
        # Exact wildcards = full admin (Owner, Contributor roles)
        if any(p == "*" or p == "*/*" for p in perms_str):
            return True
        
        # Wildcard action patterns = admin (must start with */ to be a wildcard)
        # These indicate broad administrative access across ALL resources
        admin_suffixes = ["/action", "/write", "/create", "/update"]
        for perm in perms_str:
            if perm.startswith("*/") and any(perm.endswith(suffix) for suffix in admin_suffixes):
                return True
        
        return False
    
    def get_accesstoken_from_foci(self, client_id, scopes):
        """
        Get access token from FOCI refresh token using MSAL.
        """

        app = msal.PublicClientApplication(
                client_id=client_id, authority=f"https://login.microsoftonline.com/{self.tenant_id}"
            )
        for attempt in range(3):
            try:
                return app.acquire_token_by_refresh_token(self.foci_refresh_token, scopes=scopes)
            except json.JSONDecodeError:
                if attempt < 2:
                    print(f"{Fore.YELLOW}Rate limited on token acquisition, retrying in 30s...{Fore.WHITE}")
                    time.sleep(30)
                else:
                    print(f"{Fore.RED}Rate limited on token acquisition after 3 attempts, skipping.{Fore.WHITE}")
        return {}

    def get_tokens_from_foci_with_scope(self, scope_app_ids=None):
        """
        Get a token using FOCI apps for the required resource/scopes.
        """

        for scope, app_id in (scope_app_ids or {}).items():
            token = self.get_tokens_from_foci(
                [scope],
                app_ids=app_id
            )
            if token:
                return token
        
        return None
    
    def get_tokens_from_foci(self, scopes, app_ids=None):
        """
        Get a token using FOCI apps for the required resource/scopes.
        """

        app_ids = app_ids if app_ids else FOCI_APPS
        if isinstance(app_ids, str):
            app_ids = [app_ids]
        for app_id in app_ids:
            token = (self.get_accesstoken_from_foci(
                app_id,
                scopes
            ) or {}).get("access_token")
            if token:
                return token
        
        return None


def discover_tenant_from_domain(domain):
    """
    Try to discover the tenant ID from a domain name by checking the OpenID configuration.
    Returns the tenant ID if found, otherwise None.
    """
    try:
        # Try to get tenant info from the OpenID configuration endpoint
        url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        resp = requests.get(url, timeout=(10, 30), allow_redirects=False)
        if resp.status_code == 200:
            data = resp.json()
            # Extract tenant ID from the issuer URL
            issuer = data.get("issuer", "")
            # Issuer format: https://login.microsoftonline.com/{tenant_id}/v2.0
            tenant_id = issuer.split("/")[-2] if "/" in issuer else None
            if tenant_id and tenant_id != domain:
                return tenant_id
    except Exception as e:
        pass
    return None


def get_tokens_from_az_cli(subscription_id=None):
    """Reuse the current Azure CLI session without changing its active context."""
    executable = shutil.which("az")
    if not executable:
        raise RuntimeError("Azure CLI was not found on PATH")

    env = os.environ.copy()
    env.update({
        "AZURE_CORE_COLLECT_TELEMETRY": "no",
        "AZURE_CORE_DISABLE_CONFIRM_PROMPT": "yes",
        "AZURE_CORE_NO_COLOR": "yes",
        "AZURE_CORE_ONLY_SHOW_ERRORS": "yes",
        "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
    })

    def acquire(resource_type):
        command = [
            executable,
            "account",
            "get-access-token",
            "--resource-type",
            resource_type,
            "--output",
            "json",
            "--only-show-errors",
        ]
        if subscription_id:
            command.extend(["--subscription", subscription_id])
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(re.sub(r"\s+", " ", result.stderr).strip()[:500])
        data = json.loads(result.stdout)
        token = data.get("accessToken") or data.get("access_token")
        if not token:
            raise RuntimeError(f"Azure CLI returned no {resource_type} access token")
        return token, data.get("tenant") or data.get("tenantId")

    arm_token, tenant_id = acquire("arm")
    try:
        graph_token, graph_tenant = acquire("ms-graph")
        tenant_id = tenant_id or graph_tenant
    except Exception as exc:
        print(f"{Fore.YELLOW}[!] Could not obtain a Graph token from Azure CLI: {exc}")
        graph_token = None
    return arm_token, graph_token, tenant_id


def authenticate_with_device_code(tenant_id, scope="https://management.azure.com/.default"):
    """
    Authenticate using device code flow (works with and without MFA).
    This is the default and most user-friendly authentication method.
    """
    if not tenant_id:
        print(f"{Fore.RED}Tenant ID is required for device code flow.")
        print(f"{Fore.YELLOW}Provide --tenant-id or a username with domain to auto-discover.")
        exit(1)
    
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    
    for client_id in FOCI_APPS:
        try:
            app = msal.PublicClientApplication(client_id, authority=authority)
        except ValueError as e:
            error_msg = str(e)
            if "Unable to get authority configuration" in error_msg or "invalid_tenant" in error_msg:
                print(f"{Fore.RED}Invalid tenant ID: {tenant_id}")
                print(f"{Fore.YELLOW}The tenant ID provided doesn't exist or is incorrect.")
                exit(1)
            else:
                raise
        
        # Initiate device code flow
        flow = app.initiate_device_flow(scopes=[scope])
        
        if "user_code" not in flow:
            continue
        
        print(f"\n{Fore.CYAN}To authenticate with Azure:")
        print(f"{Fore.CYAN}1. Go to: {Fore.WHITE}{flow['verification_uri']}")
        print(f"{Fore.CYAN}2. Enter code: {Fore.YELLOW}{flow['user_code']}")
        print(f"{Fore.CYAN}3. Sign in with your account (MFA will be prompted if required)")
        print(f"{Fore.CYAN}4. Return here - waiting for you to complete authentication...\n")
        
        # Wait for the user to complete the flow
        token_response = app.acquire_token_by_device_flow(flow)
        
        if "access_token" in token_response:
            print(f"{Fore.GREEN}Authentication successful!")
            tokens = {"arm_token": token_response["access_token"], "graph_token": None}
            accounts = app.get_accounts()
            if accounts:
                graph_response = app.acquire_token_silent(
                    ["https://graph.microsoft.com/.default"], account=accounts[0]
                )
                if graph_response and "access_token" in graph_response:
                    tokens["graph_token"] = graph_response["access_token"]
                else:
                    print(f"{Fore.YELLOW}Graph token was not available from the device-code session; ARM enumeration will continue.")
            return tokens
        else:
            print(f"{Fore.RED}Authentication failed:", token_response.get("error_description"))
            continue
    
    print(f"{Fore.RED}Failed to authenticate with device code flow.")
    exit(1)


def generate_foci_token(username, password, tenant_id, scope="https://management.azure.com/.default", allow_mfa_fallback=True):
    """
    Generate an access token using Microsoft Entra ID via MSAL.
    
    This function authenticates using the provided username and password
    with the Azure AD application identified by client_id in the given tenant_id.
    
    It then retrieves an access token for Microsoft Management (scope: https://management.azure.com/.default).
    
    If MFA is required and allow_mfa_fallback is True, it will automatically use device code flow for authentication.
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

        if token_response and "access_token" in token_response:
            return token_response["access_token"]
        else:
            error_desc = token_response.get("error_description") if token_response else "Unknown error"
            print(f"{Fore.RED}Error acquiring token with those credentials:", error_desc)
            exit(1)
    
    else:
        token_response = None
        for client_id in FOCI_APPS:
            # Initialize the MSAL PublicClientApplication with the client id and authority.
            try:
                app = msal.PublicClientApplication(client_id, authority=authority)
            except ValueError as e:
                error_msg = str(e)
                if "Unable to get authority configuration" in error_msg or "invalid_tenant" in error_msg:
                    print(f"{Fore.RED}Invalid tenant ID: {tenant_id}")
                    print(f"{Fore.YELLOW}The tenant ID provided doesn't exist or is incorrect.")
                    if "@" in username:
                        domain = username.split("@")[-1]
                        print(f"{Fore.CYAN}Hint: Try running without --tenant-id to auto-discover from email domain: {domain}")
                        discovered_tenant_id = discover_tenant_from_domain(domain)
                        if discovered_tenant_id:
                            print(f"{Fore.GREEN}Auto-discovered tenant ID: {discovered_tenant_id}")
                            print(f"{Fore.CYAN}Try running with: --tenant-id {discovered_tenant_id}")
                    exit(1)
                else:
                    raise
            
            # Acquire token using username/password flow
            try:
                # First try with username/password
                token_response = app.acquire_token_by_username_password(
                    username=username,
                    password=password,
                    scopes=[scope]
                )
            except Exception as e:
                continue
        
            if "access_token" in token_response:
                return token_response["access_token"]
            
            elif "error_codes" in token_response and 50126 in token_response["error_codes"]:
                print(f"{Fore.RED}Invalid credentials given. Exiting")
                exit(1)
            
            # Check if MFA is required (error codes: 50076, 50158, 50079, 50072, 50074)
            # 50076: MFA required
            # 50158: Conditional Access policy requires MFA
            # 50079: User needs to enroll for MFA
            # 50072: User needs to enroll for MFA (first time)
            # 50074: Strong authentication required
            elif "error_codes" in token_response and any(code in token_response["error_codes"] for code in [50076, 50158, 50079, 50072, 50074]):
                if not allow_mfa_fallback:
                    # MFA fallback is disabled - fail with clear error
                    print(f"{Fore.RED}MFA is required for this account, but --use-username-password does not support MFA.")
                    print(f"{Fore.YELLOW}Remove --use-username-password to use device code flow (supports MFA).")
                    exit(1)
                
                print(f"{Fore.YELLOW}MFA is required for this account. Starting device code flow...")
                
                # Use device code flow for MFA
                flow = app.initiate_device_flow(scopes=[scope])
                
                if "user_code" not in flow:
                    print(f"{Fore.RED}Failed to create device flow for MFA. Error: {flow.get('error_description')}")
                    continue
                
                print(f"\n{Fore.CYAN}To complete authentication with MFA:")
                print(f"{Fore.CYAN}1. Go to: {Fore.WHITE}{flow['verification_uri']}")
                print(f"{Fore.CYAN}2. Enter code: {Fore.YELLOW}{flow['user_code']}")
                print(f"{Fore.CYAN}3. Complete the MFA challenge in your browser")
                print(f"{Fore.CYAN}4. Return here - waiting for you to complete authentication...\n")
                
                # Wait for the user to complete the flow
                token_response = app.acquire_token_by_device_flow(flow)
                
                if "access_token" in token_response:
                    print(f"{Fore.GREEN}MFA authentication successful!")
                    return token_response["access_token"]
                else:
                    print(f"{Fore.RED}MFA authentication failed:", token_response.get("error_description"))
                    continue

        error_desc = token_response.get("error_description") if token_response else "Unknown error"
        print(f"{Fore.RED}Error acquiring token with those credentials:", error_desc)
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
    parser.add_argument('--skip-entraid', action="store_true", default=False, help="Skip EntraID permissions enumeration and only focus on Azure subscriptions")
    
    # Authentication parameters
    parser.add_argument('--username', help="Username for authentication (used with --use-username-password)")
    parser.add_argument('--password', help="Password for authentication (used with --use-username-password)")
    parser.add_argument('--use-username-password', action="store_true", default=False, help="Use username/password flow instead of device code flow (only works without MFA)")
    parser.add_argument('--use-az-cli', action="store_true", help="Reuse the current Azure CLI session (recommended when az is already logged in)")
    
    parser.add_argument('--check-only-these-subs', default="", help="In case you just want to check specific subscriptions, provide a comma-separated list of subscription IDs (e.g. 'sub1,sub2')")
    parser.add_argument('--scopes', default="", help="Known ARM resource IDs to check, comma-separated (works when resource listing is denied)")
    parser.add_argument('--azure-services', default="", help="Limit the Azure CLI read-only fallback to comma-separated top-level groups (for example: vm,keyvault,storage)")
    parser.add_argument('--skip-az-cli-fallback', action="store_true", help="Do not probe safe read-only az commands when ARM permission enumeration returns nothing")
    parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/azure_results.json)")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--no-ask', action="store_true", default=False, help="Do not ask for user input during execution, use defaults instead")
    parser.add_argument('--debug', action="store_true", help="Show failed fallback and API diagnostics")
    
    args = parser.parse_args()
    
    if args.threads < 1:
        parser.error("--threads must be at least 1")

    uuid_re = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    check_only_subs = [sub.strip() for sub in args.check_only_these_subs.split(",") if sub.strip()]
    if not all(uuid_re.fullmatch(sub) for sub in check_only_subs):
        parser.error("invalid subscription ID in --check-only-these-subs")

    known_scopes = [scope.strip() for scope in args.scopes.split(",") if scope.strip()]
    for scope in known_scopes:
        if not re.match(r"^/(subscriptions/[0-9a-fA-F-]{36}|providers/Microsoft\.Management/managementGroups/)[^?#]*$", scope, re.I):
            parser.error(f"invalid ARM resource ID in --scopes: {scope}")
    azure_services = [service.strip().lower() for service in args.azure_services.split(",") if service.strip()]

    tenant_id = args.tenant_id

    # Get tokens from environment variables if not supplied as arguments
    arm_token = args.arm_token or os.getenv("AZURE_ARM_TOKEN")
    graph_token = args.graph_token or os.getenv("AZURE_GRAPH_TOKEN")
    foci_refresh_token = args.foci_refresh_token or os.getenv("AZURE_FOCI_REFRESH_TOKEN")
    password = args.password or os.getenv("AZURE_PASSWORD")

    if args.use_az_cli and any((arm_token, graph_token, foci_refresh_token, args.use_username_password)):
        parser.error("--use-az-cli cannot be combined with token or username/password authentication")

    # Validation for username/password flow
    if args.use_username_password:
        if not args.username or not password:
            print(f"{Fore.RED}Username and password are required when using --use-username-password. Exiting.")
            exit(1)
    
    # Auto-discover tenant ID from username if provided
    if args.username and not tenant_id:
        if "@" in args.username:
            domain = args.username.split("@")[-1]
            print(f"{Fore.YELLOW}No tenant ID provided. Trying to discover from domain: {domain}")
            discovered_tenant_id = discover_tenant_from_domain(domain)
            if discovered_tenant_id:
                tenant_id = discovered_tenant_id
                print(f"{Fore.GREEN}Discovered tenant ID: {tenant_id}")
            else:
                print(f"{Fore.YELLOW}Could not discover tenant ID from domain. Using domain as tenant: {domain}")
                tenant_id = domain

    # If no tokens are provided, use authentication flow
    if not arm_token and not graph_token and not foci_refresh_token:
        if args.use_az_cli:
            print(f"{Fore.CYAN}Reusing the current Azure CLI login (no active subscription will be changed).")
            try:
                token_sub = check_only_subs[0] if check_only_subs else None
                arm_token, graph_token, cli_tenant = get_tokens_from_az_cli(token_sub)
                tenant_id = tenant_id or cli_tenant
            except Exception as exc:
                print(f"{Fore.RED}Could not reuse the Azure CLI session: {exc}")
                exit(1)
        elif args.use_username_password:
            # Use username/password flow (only works without MFA)
            if not args.username or not password:
                print(f"{Fore.RED}Username and password are required for username/password authentication. Exiting.")
                exit(1)
            
            if not tenant_id:
                print(f"{Fore.RED}Tenant ID is required. Provide --tenant-id or use username with domain to auto-discover. Exiting.")
                exit(1)
            
            print(f"{Fore.CYAN}Using username/password authentication (note: will fail if MFA is required)...")
            arm_token = generate_foci_token(args.username, password, tenant_id, allow_mfa_fallback=False)
            try:
                graph_token = generate_foci_token(args.username, password, tenant_id, scope="https://graph.microsoft.com/.default", allow_mfa_fallback=False)
            except Exception:
                print(f"{Fore.YELLOW}Graph token could not be acquired; ARM enumeration will continue.")
        
        else:
            # Use device code flow (default - works with and without MFA)
            no_ask = args.no_ask
            print(f"{Fore.CYAN}No tokens provided. Using device code flow for authentication...")
            print(f"{Fore.CYAN}(This works with and without MFA)")
            
            if not tenant_id:
                print(f"{Fore.YELLOW}Tenant ID is required for authentication.")
                print(f"{Fore.YELLOW}Provide --tenant-id <tenant_id> or use a common tenant:")
                if no_ask:
                    tenant_id = "organizations"
                    print(f"{Fore.GREEN}Using 'organizations' tenant (works for most Azure AD accounts)")
                else:
                    tenant_id = input(f"{Fore.CYAN}Enter tenant ID (or press Enter to use 'organizations'): {Fore.WHITE}").strip()
                    if not tenant_id:
                        tenant_id = "organizations"
                        print(f"{Fore.GREEN}Using 'organizations' tenant (works for most Azure AD accounts)")
            
            tokens = authenticate_with_device_code(tenant_id)
            arm_token = tokens.get("arm_token")
            graph_token = tokens.get("graph_token")
        
    
    # Initialize and run the AzurePEASS analysis
    azure_peass = AzurePEASS(
        arm_token,
        graph_token,
        foci_refresh_token,
        tenant_id,
        very_sensitive_combinations,  # Ensure these variables are defined in your context
        sensitive_combinations,       # Ensure these variables are defined in your context
        num_threads=args.threads,
        not_enumerate_m365=args.not_enumerate_m365,
        skip_entraid=args.skip_entraid,
        out_path=args.out_json_path,
        check_only_subs=check_only_subs,
        no_ask=args.no_ask,
        known_scopes=known_scopes,
        use_az_cli=args.use_az_cli,
        skip_az_cli_fallback=args.skip_az_cli_fallback,
        azure_services=azure_services,
        debug=args.debug,
    )
    azure_peass.run_analysis()
