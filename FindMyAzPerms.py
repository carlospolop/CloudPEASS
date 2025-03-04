#!/usr/bin/env python3
"""
Azure Resource and Management Group Permissions Audit Script.

This script uses an Azure Management API access token to:
  1. List all subscriptions the user can access.
  2. For each subscription, enumerate all resources (with optional filtering) and check the user's permissions.
  3. Check permissions over the subscription itself if not present in the resources list.
  4. List all management groups and check the user's permissions on them.

Usage:
    python azure_perms_audit.py --token <AZURE_MANAGEMENT_TOKEN> [--threads N] [--filter-type TYPE] [--json]

Example:
    python azure_perms_audit.py --token eyJhbGciOi... --threads 8 --filter-type Microsoft.Compute/virtualMachines

Note:
- The token should be an Azure AD token for the Azure Resource Manager (https://management.azure.com).
- Avoid exposing the token in shell history; consider using environment variables or prompting for input in practice.
"""
import argparse
import requests
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional coloring for structured output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    Fore = Style = None

# API versions
SUBS_API_VERSION = "2020-01-01"         # Subscriptions
RESOURCES_API_VERSION = "2021-04-01"      # Resources in subscriptions
MG_API_VERSION = "2020-05-01"             # Management Groups
PERMS_API_VERSION = "2022-04-01"          # Permissions

def get_subscriptions(session):
    """Fetch all subscriptions accessible with the given credentials."""
    url = f"https://management.azure.com/subscriptions?api-version={SUBS_API_VERSION}"
    try:
        resp = session.get(url, timeout=10)
    except requests.RequestException as e:
        raise SystemExit(f"Network error while fetching subscriptions: {e}")
    if resp.status_code != 200:
        raise SystemExit(f"Failed to list subscriptions (HTTP {resp.status_code}): {resp.text}")
    data = resp.json()
    subscriptions = data.get("value", [])
    next_link = data.get("nextLink")
    while next_link:
        try:
            resp = session.get(next_link, timeout=10)
        except requests.RequestException as e:
            raise SystemExit(f"Network error on fetching subscriptions page: {e}")
        if resp.status_code != 200:
            raise SystemExit(f"Failed to fetch subscriptions page (HTTP {resp.status_code}): {resp.text}")
        data = resp.json()
        subscriptions.extend(data.get("value", []))
        next_link = data.get("nextLink")
    return subscriptions

def get_resources(session, sub_id, filter_type=None):
    """Fetch all resources in a given subscription. Optionally filter by resource type."""
    base_url = f"https://management.azure.com/subscriptions/{sub_id}/resources"
    params = {"api-version": RESOURCES_API_VERSION}
    if filter_type:
        params["$filter"] = f"resourceType eq '{filter_type}'"
    resources = []
    url = base_url
    try:
        resp = session.get(url, params=params, timeout=15)
    except requests.RequestException as e:
        print(f"Error: Network issue while listing resources for subscription {sub_id}: {e}", file=sys.stderr)
        return resources
    if resp.status_code == 403:
        print(f"Warning: Access denied to subscription {sub_id}. Skipping it.", file=sys.stderr)
        return resources
    if resp.status_code != 200:
        print(f"Warning: Failed to list resources for subscription {sub_id} (HTTP {resp.status_code}).", file=sys.stderr)
        return resources
    data = resp.json()
    resources.extend(data.get("value", []))
    next_link = data.get("nextLink")
    while next_link:
        try:
            resp = session.get(next_link, timeout=15)
        except requests.RequestException as e:
            print(f"Error: Network issue while fetching more resources for {sub_id}: {e}", file=sys.stderr)
            break
        if resp.status_code != 200:
            print(f"Warning: Failed to fetch all resource pages for {sub_id} (HTTP {resp.status_code}).", file=sys.stderr)
            break
        data = resp.json()
        resources.extend(data.get("value", []))
        next_link = data.get("nextLink")
    return resources

def get_management_groups(session):
    """Fetch all management groups accessible with the given credentials."""
    url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version={MG_API_VERSION}"
    try:
        resp = session.get(url, timeout=15)
    except requests.RequestException as e:
        print(f"Error: Network issue while listing management groups: {e}", file=sys.stderr)
        return []
    if resp.status_code != 200:
        print(f"Warning: Failed to list management groups (HTTP {resp.status_code}): {resp.text}", file=sys.stderr)
        return []
    data = resp.json()
    mgroups = data.get("value", [])
    next_link = data.get("nextLink")
    while next_link:
        try:
            resp = session.get(next_link, timeout=15)
        except requests.RequestException as e:
            print(f"Error: Network issue while fetching management groups page: {e}", file=sys.stderr)
            break
        if resp.status_code != 200:
            print(f"Warning: Failed to fetch all management groups (HTTP {resp.status_code}).", file=sys.stderr)
            break
        data = resp.json()
        mgroups.extend(data.get("value", []))
        next_link = data.get("nextLink")
    return mgroups

def get_resource_permissions(session, resource_id):
    """Get allowed actions for the current user on the specified resource."""
    url = f"https://management.azure.com{resource_id}/providers/Microsoft.Authorization/permissions?api-version={PERMS_API_VERSION}"
    try:
        resp = session.get(url, timeout=10)
    except requests.RequestException as e:
        return {"error": f"Network error: {e}"}
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    perm_data = resp.json()
    permissions = perm_data.get("value", [])
    return {"permissions": permissions}

def parse_resource_id(resource_id):
    """Extract the resource group name from a resource ID, if present."""
    rg_name = None
    parts = resource_id.split("/")
    if "resourceGroups" in parts:
        rg_index = parts.index("resourceGroups")
        if rg_index + 1 < len(parts):
            rg_name = parts[rg_index + 1]
    return rg_name

def main():
    parser = argparse.ArgumentParser(
        description="List Azure subscriptions/resources and management groups, then check user permissions using Azure REST API."
    )
    parser.add_argument("--token", required=True, help="Azure management API token (Bearer token for ARM).")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for concurrent permission checks (default: 4).")
    parser.add_argument("--filter-type", help="Filter by resource type (e.g., 'Microsoft.Compute/virtualMachines').")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format (default is colored structured output).")
    args = parser.parse_args()

    token = args.token
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})

    # === Subscriptions and Resources ===
    subscriptions = get_subscriptions(session)
    if not subscriptions:
        print("No subscriptions found for the provided token.")
    subs_results = []  # Final subscription results
    tasks = []         # Tasks for subscription resource permission checks

    for sub in subscriptions:
        sub_id = sub.get("subscriptionId") or sub.get("id")
        sub_name = sub.get("displayName", "<unknown>")
        if not sub_id:
            continue
        if sub_id.startswith("/subscriptions/"):
            sub_id = sub_id.split("/")[2]
        sub_record = {
            "subscriptionId": sub_id,
            "subscriptionName": sub_name,
            "resources": []
        }
        resource_list = get_resources(session, sub_id, filter_type=args.filter_type)

        # Ensure the subscription itself is included
        sub_resource_id = f"/subscriptions/{sub_id}"
        if not any(res.get("id", "").lower() == sub_resource_id.lower() for res in resource_list):
            resource_list.append({
                "id": sub_resource_id,
                "name": sub_name,
                "type": "Microsoft.Subscription/subscriptions",
                "resourceGroup": "N/A"
            })

        for res in resource_list:
            res_id = res.get("id")
            res_name = res.get("name")
            res_type = res.get("type")
            rg_name = parse_resource_id(res_id) if res_id else None
            resource_info = {
                "id": res_id,
                "name": res_name,
                "type": res_type,
                "resourceGroup": rg_name
            }
            tasks.append((sub_record, resource_info))
        subs_results.append(sub_record)

    # === Management Groups ===
    mgroups = get_management_groups(session)
    mg_results = []  # To hold management group permission results
    mg_tasks = []    # Tasks for mg permission checks

    for mg in mgroups:
        # mg structure typically contains an "id" like " /providers/Microsoft.Management/managementGroups/<mgId>"
        mg_id = mg.get("id")
        mg_name = mg.get("name", mg_id)
        if not mg_id:
            continue
        mg_record = {
            "managementGroupId": mg_id,
            "managementGroupName": mg_name,
            "permissions": {}  # to be filled in
        }
        mg_tasks.append((mg_record, mg_id))
        mg_results.append(mg_record)

    # === Concurrent Permission Checks ===
    max_workers = max(1, args.threads)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Subscription resource tasks
        future_to_resource = {
            executor.submit(get_resource_permissions, session, res_info["id"]): (sub_rec, res_info)
            for (sub_rec, res_info) in tasks
        }
        for future in as_completed(future_to_resource):
            sub_record, res_info = future_to_resource[future]
            perm_result = future.result()
            res_info.update(perm_result)
            sub_record["resources"].append(res_info)

        # Management group tasks
        future_to_mg = {
            executor.submit(get_resource_permissions, session, mg_id): mg_record
            for (mg_record, mg_id) in mg_tasks
        }
        for future in as_completed(future_to_mg):
            mg_record = future_to_mg[future]
            mg_record["permissions"] = future.result()

    # === Output Results ===
    final_output = {
        "subscriptions": subs_results,
        "managementGroups": mg_results
    }

    if args.json:
        print(json.dumps(final_output, indent=2))
    else:
        # Print subscription results
        print("\n=== Subscriptions and Resources ===")
        for sub in subs_results:
            sub_id = sub["subscriptionId"]
            sub_name = sub.get("subscriptionName", sub_id)
            if Fore and Style:
                print(f"{Style.BRIGHT}{Fore.CYAN}Subscription: {sub_name} (ID: {sub_id}){Style.RESET_ALL}")
            else:
                print(f"Subscription: {sub_name} (ID: {sub_id})")
            for res in sub["resources"]:
                name = res.get("name", "")
                rtype = res.get("type", "")
                rg = res.get("resourceGroup") or "N/A"
                if "error" in res:
                    perm_info = f"ERROR: {res['error']}"
                else:
                    perm_entries = res.get("permissions", [])
                    all_actions = set()
                    all_data_actions = set()
                    full_access = False
                    exclusions = set()
                    for perm in perm_entries:
                        actions = perm.get("actions", [])
                        not_actions = perm.get("notActions", [])
                        data_actions = perm.get("dataActions", [])
                        not_data_actions = perm.get("notDataActions", [])
                        if "*" in actions:
                            full_access = True
                            for na in not_actions:
                                exclusions.add(na)
                        else:
                            all_actions.update(actions)
                        if "*" in data_actions:
                            full_access = True
                            for nda in not_data_actions:
                                exclusions.add(nda)
                        else:
                            all_data_actions.update(data_actions)
                    if full_access:
                        if exclusions:
                            excl_list = ", ".join(sorted(exclusions))
                            perm_info = f"All actions (except: {excl_list})"
                        else:
                            perm_info = "All actions"
                    else:
                        if all_actions:
                            actions_list = sorted(all_actions)
                            if len(actions_list) > 10:
                                shown = ", ".join(actions_list[:10])
                                perm_info = f"Allowed actions: {shown}, ... (+{len(actions_list)-10} more)"
                            else:
                                perm_info = "Allowed actions: " + ", ".join(actions_list)
                        else:
                            perm_info = "No management actions allowed"
                        if all_data_actions:
                            data_list = sorted(all_data_actions)
                            if len(data_list) > 5:
                                shown = ", ".join(data_list[:5])
                                perm_info += f"; Data actions: {shown}, ... (+{len(data_list)-5} more)"
                            else:
                                perm_info += "; Data actions: " + ", ".join(data_list)
                if Fore and Style:
                    resource_str = (f"  - {Fore.GREEN}{name}{Style.RESET_ALL} "
                                    f"[{Fore.CYAN}{rtype}{Style.RESET_ALL}, RG: {Fore.YELLOW}{rg}{Style.RESET_ALL}]"
                                    f": {perm_info}")
                else:
                    resource_str = f"  - {name} [{rtype}, RG: {rg}]: {perm_info}"
                print(resource_str)

        # Print management group results
        print("\n=== Management Groups ===")
        for mg in mg_results:
            mg_id = mg.get("managementGroupId")
            mg_name = mg.get("managementGroupName", mg_id)
            if Fore and Style:
                print(f"{Style.BRIGHT}{Fore.MAGENTA}Management Group: {mg_name} (ID: {mg_id}){Style.RESET_ALL}")
            else:
                print(f"Management Group: {mg_name} (ID: {mg_id})")
            perms = mg.get("permissions", {})
            if "error" in perms:
                print(f"  ERROR: {perms['error']}")
            else:
                perm_entries = perms.get("permissions", [])
                all_actions = set()
                all_data_actions = set()
                full_access = False
                exclusions = set()
                for perm in perm_entries:
                    actions = perm.get("actions", [])
                    not_actions = perm.get("notActions", [])
                    data_actions = perm.get("dataActions", [])
                    not_data_actions = perm.get("notDataActions", [])
                    if "*" in actions:
                        full_access = True
                        for na in not_actions:
                            exclusions.add(na)
                    else:
                        all_actions.update(actions)
                    if "*" in data_actions:
                        full_access = True
                        for nda in not_data_actions:
                            exclusions.add(nda)
                    else:
                        all_data_actions.update(data_actions)
                if full_access:
                    if exclusions:
                        excl_list = ", ".join(sorted(exclusions))
                        perm_info = f"All actions (except: {excl_list})"
                    else:
                        perm_info = "All actions"
                else:
                    if all_actions:
                        actions_list = sorted(all_actions)
                        if len(actions_list) > 10:
                            shown = ", ".join(actions_list[:10])
                            perm_info = f"Allowed actions: {shown}, ... (+{len(actions_list)-10} more)"
                        else:
                            perm_info = "Allowed actions: " + ", ".join(actions_list)
                    else:
                        perm_info = "No management actions allowed"
                    if all_data_actions:
                        data_list = sorted(all_data_actions)
                        if len(data_list) > 5:
                            shown = ", ".join(data_list[:5])
                            perm_info += f"; Data actions: {shown}, ... (+{len(data_list)-5} more)"
                        else:
                            perm_info += "; Data actions: " + ", ".join(data_list)
                print("  " + perm_info)

if __name__ == "__main__":
    main()
