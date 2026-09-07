import json
from collections import defaultdict
from tqdm import tqdm
import time
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import pdb
import faulthandler
from pathlib import Path
import yaml
from typing import Optional


from colorama import Fore, Style, init, Back
from .permission_risk_classifier import classify_all, classify_permission

init(autoreset=True)
faulthandler.enable()


class CloudResource:
    """
    Standardized resource representation across all cloud providers.
    Ensures consistent JSON output format for AWS, Azure, and GCP.
    """
    def __init__(self, resource_id: str, name: str, resource_type: str, 
                 permissions: list = None, deny_perms: list = None, is_admin: bool = False, **extra_fields):
        self.id = resource_id
        self.name = name
        self.type = resource_type
        self.permissions = permissions or []
        self.deny_perms = deny_perms or []
        self.is_admin = is_admin
        # Store any extra fields (like assignmentType for Azure EntraID)
        self.extra_fields = extra_fields
    
    def to_dict(self) -> dict:
        """Convert resource to dictionary for JSON serialization."""
        result = {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "permissions": self.permissions,
            "deny_perms": self.deny_perms,
            "is_admin": self.is_admin
        }
        # Add any extra fields
        result.update(self.extra_fields)
        return result
    
    @classmethod
    def from_dict(cls, data: dict):
        """Create CloudResource from dictionary."""
        resource_id = data.pop("id", "")
        name = data.pop("name", "")
        resource_type = data.pop("type", "")
        permissions = data.pop("permissions", [])
        deny_perms = data.pop("deny_perms", [])
        is_admin = data.pop("is_admin", False)
        # Everything else goes to extra_fields
        return cls(resource_id, name, resource_type, permissions, deny_perms, is_admin, **data)

def my_thread_excepthook(args):
    print(f"Exception in thread {args.thread.name}: {args.exc_type.__name__}: {args.exc_value}")
    # Start the post-mortem debugger session.
    pdb.post_mortem(args.exc_traceback)

threading.excepthook = my_thread_excepthook


class CloudPEASS:
    def __init__(self, very_sensitive_combos, sensitive_combos, cloud_provider, num_threads, out_path=None):
        self.very_sensitive_combos = [set(combo) for combo in very_sensitive_combos]
        self.sensitive_combos = [set(combo) for combo in sensitive_combos]
        self.cloud_provider = cloud_provider
        self.num_threads = int(num_threads)
        self.out_path = out_path
        self.principal_info = {}

    def get_resources_and_permissions(self):
        """
        Abstract method to collect resources and permissions. Must be implemented per cloud.

        Returns:
            list: List of resource dictionaries containing resource IDs, names, types, and permissions.
        """
        raise NotImplementedError("Implement this method per cloud provider.")

    def print_whoami_info(self):
        """
        Abstract method to print information about the principal used.

        Returns:
            dict: Informationa about the user or principal used to run the analysis.
        """
        raise NotImplementedError("Implement this method per cloud provider.")

    @staticmethod
    def group_resources_by_permissions(resources):
        """
        First group entries by resources and then group them by their unique sets of permissions.
        This is done to reduce the number of entries and make the analysis more efficient.

        Args:
            resources (list): List of CloudResource objects or dictionaries with permissions.

        Returns:
            dict: Keys as frozensets of permissions, values as lists of resources with those permissions.
        """

        # Group by affected resources first
        final_resources = {}
        for resource in resources:
            # Convert CloudResource-like objects to dict if needed (avoid brittle isinstance checks across import paths)
            if not isinstance(resource, dict) and hasattr(resource, "to_dict"):
                resource = resource.to_dict()
            
            resource_id = resource["id"]
            resource_type = resource["type"]
            resource_name = resource["name"]
            is_admin = resource.get("is_admin", False)
            if resource_id not in final_resources:
                final_resources[resource_id] = {
                    "id": resource_id,
                    "type": resource_type,
                    "name": resource_name,
                    "permissions": set(),
                    "deny_perms": set(),
                    "is_admin": is_admin
                }
            else:
                # If resource already exists and either the existing or new one is admin, mark as admin
                if is_admin:
                    final_resources[resource_id]["is_admin"] = True
            final_resources[resource_id]["permissions"].update(resource["permissions"])
            final_resources[resource_id]["deny_perms"].update(resource.get("deny_perms", []))


        grouped = defaultdict(list)
        for resource in final_resources.values():
            perms_set = frozenset(resource["permissions"])
            deny_perms_set = frozenset(resource.get("deny_perms", []))
            
            # Add in perms_set the deny permissions adding the prefix "-"
            perms_set = perms_set.union({"-" + perm for perm in deny_perms_set})
            
            if perms_set:
                grouped[perms_set].append(resource)
        return grouped

    def analyze_sensitive_combinations(self, permissions):
        found_very_sensitive = set()
        found_sensitive = set()

        # Check very sensitive combinations (with wildcard support)
        ## Wildcards can be used in the our ahrdcoded patterns or also in AWS permissions, so both are checked
        for combo in self.very_sensitive_combos:
            if all(any(fnmatch.fnmatch(perm, pattern) or fnmatch.fnmatch(pattern, perm) for perm in permissions) for pattern in combo):
                for pattern in combo:
                    for perm in permissions:
                        if fnmatch.fnmatch(perm, pattern):
                            found_very_sensitive.add(perm)

        # Check sensitive combinations (with wildcard support)
        for combo in self.sensitive_combos:
            if all(any(fnmatch.fnmatch(perm, pattern) or fnmatch.fnmatch(pattern, perm) for perm in permissions) for pattern in combo):
                for pattern in combo:
                    for perm in permissions:
                        if fnmatch.fnmatch(perm, pattern):
                            found_sensitive.add(perm)

        # Also use the new risk classifier from Blue-PEASS
        try:
            cloud_id = self.cloud_provider.lower().strip()
            if cloud_id in {"aws", "azure", "gcp"}:
                risk_categories = classify_all(cloud_id, permissions, unknown_default="medium")
                # Add critical and high risk permissions to sensitive sets
                for perm in risk_categories.get("critical", []):
                    found_very_sensitive.add(perm)
                for perm in risk_categories.get("high", []):
                    found_sensitive.add(perm)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Couldn't classify permissions with risk classifier: {e}")

        found_sensitive -= found_very_sensitive  # Avoid duplicates

        return {
            "very_sensitive_perms": found_very_sensitive,
            "sensitive_perms": found_sensitive
        }

    def categorize_permissions_from_catalog(self, permissions):
        """
        Categorize permissions using the Blue-PEASS risk classifier.
        Downloads risk_rules YAML patterns from Blue-PEASS repo at runtime.
        """
        cloud_id = self.cloud_provider.lower().strip()
        if cloud_id not in {"aws", "azure", "gcp"}:
            return {"critical": set(), "high": set(), "medium": set(), "low": set()}
        
        try:
            # Use the new classifier from Blue-PEASS
            risk_categories = classify_all(cloud_id, permissions, unknown_default="medium")
            # Convert lists to sets for compatibility
            return {
                "critical": set(risk_categories.get("critical", [])),
                "high": set(risk_categories.get("high", [])),
                "medium": set(risk_categories.get("medium", [])),
                "low": set(risk_categories.get("low", [])),
            }
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Couldn't classify permissions: {e}")
            return {"critical": set(), "high": set(), "medium": set(), "low": set()}

    def sumarize_resources(self, resources):
        """
        Summarize resources by reducing to 1 resource per type.

        Args:
            resources (list): List of resource dictionaries.

        Returns:
            dict: Summary of resources .
        """

        res = {}

        if self.cloud_provider.lower() == "azure":
            for r in resources:
                if len(r.split("/")) == 3:
                    res["subscription"] = r
                elif len(r.split("/")) == 5:
                    res["resource_group"] = r
                elif "#microsoft.graph" in r:
                    r_type = r.split(":")[-1] # Microsoft.Graph object
                    res[r_type] = r
                else: 
                    r_type = r.split("/providers/")[1].split("/")[0] # Microsoft.Storage
                    res[r_type] = r
        
        elif self.cloud_provider.lower() == "gcp":
            for r in resources:
                if len(r.split("/")) == 2:
                    res["project"] = r
                else: 
                    r_type = r.split("/")[2] # serviceAccounts
                    res[r_type] = r
        
        elif self.cloud_provider.lower() == "aws":
            pass

        else:
            raise ValueError("Unsupported cloud provider. Supported providers are: Azure, AWS, GCP.")
        
        return res



    def analyze_group(self, perms_set, resources_group):
        sensitive_perms = self.analyze_sensitive_combinations(perms_set)
        sensitive_perms_serializable = {
            "very_sensitive_perms": sorted(sensitive_perms["very_sensitive_perms"]),
            "sensitive_perms": sorted(sensitive_perms["sensitive_perms"]),
        }
        perms_catalog = self.categorize_permissions_from_catalog(perms_set)
        perms_catalog["critical"].update(sensitive_perms["very_sensitive_perms"])
        perms_catalog["high"].update(sensitive_perms["sensitive_perms"])
        perms_catalog["high"] -= perms_catalog["critical"]
        perms_catalog["medium"] -= (perms_catalog["critical"] | perms_catalog["high"])
        perms_catalog["low"] -= (perms_catalog["critical"] | perms_catalog["high"] | perms_catalog["medium"])
        # Some providers/tools can return permissions not present in the built-in catalog.
        # Treat uncategorized permissions as low-risk so UIs can still show accurate counts.
        categorized = set()
        for v in perms_catalog.values():
            categorized |= set(v)
        uncategorized = set(perms_set) - categorized
        if uncategorized:
            perms_catalog["low"].update(uncategorized)

        # Convert CloudResource objects to dicts for resource IDs
        resource_ids = []
        is_admin = False
        for r in resources_group:
            r_dict = r.to_dict() if isinstance(r, CloudResource) else r
            # Debug: Check if we're properly detecting is_admin
            if r_dict.get("is_admin", False):
                is_admin = True
            if r_dict["id"]:
                resource_ids.append(r_dict["id"])
            else:
                resource_ids.append(r_dict["id"] + ":" + r_dict["type"] + ":" + r_dict["name"])

        return {
            "principal": self.principal_info,
            "permissions": list(perms_set),
            "resources": resource_ids,
            "sensitive_perms": sensitive_perms_serializable,
            "permissions_cat": {k: sorted(v) for k, v in perms_catalog.items()},
            "is_admin": is_admin
        }
    

    def run_analysis(self):
        print(f"{Fore.GREEN}\nStarting CloudPEASS analysis for {self.cloud_provider}...")
        print(f"{Fore.YELLOW}[{Fore.BLUE}i{Fore.YELLOW}] If you want to learn cloud hacking, check out the trainings at {Fore.CYAN}https://training.hacktricks.xyz")
        
        print(f"{Fore.MAGENTA}\nGetting information about your principal...")
        whoami = self.print_whoami_info()
        self.principal_info = whoami if isinstance(whoami, dict) else {}
        
        print(f"{Fore.MAGENTA}\nGetting all your permissions...")
        resources = self.get_resources_and_permissions()
        final_resources = []
        has_admin = False
        for resource in resources:
            # Handle CloudResource-like objects and dictionaries (avoid brittle isinstance checks across import paths)
            if hasattr(resource, "permissions") and hasattr(resource, "is_admin"):
                perms = getattr(resource, "permissions")
                is_admin = getattr(resource, "is_admin")
            elif isinstance(resource, dict):
                perms = resource.get("permissions", [])
                is_admin = resource.get("is_admin", False)
            else:
                perms = []
                is_admin = False
            
            if is_admin:
                has_admin = True
            deny_perms = (
                getattr(resource, "deny_perms", [])
                if hasattr(resource, "deny_perms")
                else resource.get("deny_perms", []) if isinstance(resource, dict) else []
            )
            if perms or deny_perms:
                final_resources.append(resource)
        resources = final_resources

        grouped_resources = self.group_resources_by_permissions(resources)
        total_permissions = sum(len(perms_set) for perms_set in grouped_resources.keys())
        print(f"{Fore.YELLOW}\nFound {Fore.GREEN}{len(resources)} {Fore.YELLOW}resources with a total of {Fore.GREEN}{total_permissions} {Fore.YELLOW}permissions.")
        
        all_critical_perms = set()
        all_high_perms = set()
        all_medium_perms = set()

        analysis_results = []
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_group = {
                executor.submit(self.analyze_group, perms_set, resources_group): perms_set
                for perms_set, resources_group in grouped_resources.items()
            }

            for future in tqdm(as_completed(future_to_group), total=len(future_to_group), desc="Analyzing Permissions"):
                result = future.result()
                analysis_results.append(result)

        if self.out_path:
            with open(self.out_path, "w") as f:
                json.dump(analysis_results, f, indent=2)
            print(f"{Fore.GREEN}Results saved to {self.out_path}")

        # Clearly Print the results with the requested color formatting
        print(f"{Fore.YELLOW}\nDetailed Analysis Results:\n")
        print(f"{Fore.BLUE}Legend:")
        print(f"{Fore.RED}  {Back.YELLOW}Critical Permissions{Style.RESET_ALL} - Very dangerous permissions that often allow privilege escalation or access to secrets/credentials.")
        print(f"{Fore.RED}  High Permissions{Style.RESET_ALL} - Sensitive permissions that can enable attacks depending on context.")
        print(f"{Fore.YELLOW}  Medium Permissions{Style.RESET_ALL} - Interesting permissions that can support attacks in some scenarios.")
        print(f"{Fore.WHITE}  Low/Other Permissions{Style.RESET_ALL} - Less interesting permissions.")
        print()
        print()
        for result in analysis_results:
            perms = result["permissions"]
            perms_cat = result.get("permissions_cat") or {}
            critical = set(perms_cat.get("critical") or [])
            high = set(perms_cat.get("high") or [])
            medium = set(perms_cat.get("medium") or [])
            all_critical_perms.update(critical)
            all_high_perms.update(high)
            all_medium_perms.update(medium)

            print(f"{Fore.WHITE}Resources: {Fore.CYAN}{f'{Fore.WHITE} , {Fore.CYAN}'.join(result['resources'])}")
            
            # Organize permissions by category
            critical_perms = []
            high_perms = []
            medium_perms = []
            low_perms = []
            
            for perm in perms:
                if perm in critical:
                    critical_perms.append(perm)
                elif perm in high:
                    high_perms.append(perm)
                elif perm in medium:
                    medium_perms.append(perm)
                else:
                    low_perms.append(perm)
            
            max_per_category = getattr(self, "max_permissions_per_category", None)
            if max_per_category:
                def print_category(label, values, color):
                    ordered = sorted(values)
                    shown = ordered[:max_per_category]
                    print(
                        f"{color}{label} ({len(ordered)}){Style.RESET_ALL}: "
                        f"{Fore.WHITE}{', '.join(shown) if shown else 'none'}"
                    )
                    if len(ordered) > len(shown):
                        print(
                            f"{Fore.BLUE}  ... {len(ordered) - len(shown)} more {label.lower()} "
                            "permission(s); use --out-json-path for the complete list."
                        )

                print_category("Critical", critical_perms, Fore.RED + Back.YELLOW)
                print_category("High", high_perms, Fore.RED)
                print_category("Medium", medium_perms, Fore.YELLOW)
                print_category("Low/other", low_perms, Fore.WHITE)
                print("\n" + Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)
                continue

            # Build permissions message with sorted categories
            perms_msg = f"{Fore.WHITE}Permissions: "
            
            for perm in critical_perms:
                perms_msg += f"{Fore.RED}{Back.YELLOW}{perm}{Style.RESET_ALL}, "
            
            for perm in high_perms:
                perms_msg += f"{Fore.RED}{perm}{Style.RESET_ALL}, "
            
            for perm in medium_perms:
                perms_msg += f"{Fore.YELLOW}{perm}{Style.RESET_ALL}, "
            
            for perm in low_perms:
                perms_msg += f"{Fore.WHITE}{perm}{Style.RESET_ALL}, "
            
            perms_msg = perms_msg.strip()
            if perms_msg.endswith(","):
                perms_msg = perms_msg[:-1]
            perms_msg += Style.RESET_ALL
            
            print(perms_msg)
            print("\n" + Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)

        if not analysis_results:
            print(f"{Fore.RED}No permissions found. Exiting.")

        # Exit successfully
        print(f"{Fore.GREEN}\nAnalysis completed successfully!")
        print()
        print(f"{Fore.YELLOW}If you want to learn more about cloud hacking, check out the trainings at {Fore.CYAN}https://training.hacktricks.xyz")
        exit(0)
