import json
import requests
from collections import defaultdict
from tqdm import tqdm
import time
import requests
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import pdb
import faulthandler

from colorama import Fore, Style, init, Back

init(autoreset=True)
faulthandler.enable()

HACKTRICKS_AI_ENDPOINT = "https://www.hacktricks.ai/api/ht-api"

SENSITIVE_RESPONSE_FORMAT = """\n
### RESPONSE FORMAT
Your complete response must be a valid JSON with the following format:

[
    {
        "permission": "Permission string",
        "is_very_sensitive": true/false,
        "is_sensitive": true/false,
        "description": "Description of why it is sensitive"
    },
    [...]
]


### EXAMPLE RESPONSE

__CLOUD_SPECIFIC_EXAMPLE__


### CLARIFICATIONS
Remember to indicate as many sensitive permissions as possible.
Always recheck the permissions and their descriptions to ensure they are correct and avoid false positives.
If no malicious actions are found, please provide an empty JSON array: []

"""

MALICIOUS_ACTIONS_RESPONSE_FORMAT = """\n
### RESPONSE FORMAT

Your complete response must be a valid JSON with the following format:
[
    {
        "Title": "Malicious Action Title",
        "Description": "Description of the malicious action",
        "Commands": "Bash commands (using azure-cli, aws-cli, gcloud, etc.) to perform the malicious action",
    },
    [...]
]

### EXAMPLE RESPONSE

__CLOUD_SPECIFIC_EXAMPLE__


### CLARIFICATIONS
Remember to indicate as many malicious actions as possible, and provide the necessary commands to perform them.
If more than one command is needed, just separate them with a newline character or a semi-colon.
Always recheck the response to ensure it's correct and avoid false positives.

If no malicious actions are found, please provide an empty JSON array: []
"""


def my_thread_excepthook(args):
    print(f"Exception in thread {args.thread.name}: {args.exc_type.__name__}: {args.exc_value}")
    # Start the post-mortem debugger session.
    pdb.post_mortem(args.exc_traceback)

threading.excepthook = my_thread_excepthook


class CloudPEASS:
    def __init__(self, very_sensitive_combos, sensitive_combos, cloud_provider, not_use_ht_ai, num_threads, example_malicious_cloud_response, example_sensitive_cloud_response, out_path=None):
        self.very_sensitive_combos = [set(combo) for combo in very_sensitive_combos]
        self.sensitive_combos = [set(combo) for combo in sensitive_combos]
        self.cloud_provider = cloud_provider
        self.not_use_ht_ai = not_use_ht_ai
        self.num_threads = int(num_threads)
        self.out_path = out_path
        self.malicious_actions_response_format = MALICIOUS_ACTIONS_RESPONSE_FORMAT.replace("__CLOUD_SPECIFIC_EXAMPLE__", example_malicious_cloud_response)
        self.sensitive_response_format = SENSITIVE_RESPONSE_FORMAT.replace("__CLOUD_SPECIFIC_EXAMPLE__", example_sensitive_cloud_response)
        self._rate_limit_lock = threading.Lock()
        self._request_timestamps = []  

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
        Group resources by their unique sets of permissions.

        Args:
            resources (list): List of resource dictionaries with permissions.

        Returns:
            dict: Keys as frozensets of permissions, values as lists of resources with those permissions.
        """
        grouped = defaultdict(list)
        for resource in resources:
            perms_set = frozenset(resource["permissions"])
            deny_perms_set = set()
            if "deny_perms" in resource:
                deny_perms_set = frozenset(resource["deny_perms"])
            
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

        found_sensitive -= found_very_sensitive  # Avoid duplicates

        return {
            "very_sensitive_perms": found_very_sensitive,
            "sensitive_perms": found_sensitive
        }

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



    def find_attacks_from_permissions(self, permissions, resources):
        """
        Query Hacktricks AI to analyze malicious actions for a set of permissions.

        Args:
            permissions (list): List of permission strings.
            cloud_provider (str): 'Azure', 'AWS', or 'GCP'.

        Returns:
            dict: Analysis result containing impact description or None if nothing found.
        """

        sum_resources = self.sumarize_resources(resources)

        query_text = "#### CONTEXT\n"
        query_text += f"Given the following {self.cloud_provider} permissions: {', '.join(permissions)}\n"
        if sum_resources:
            query_text = f"Over the following resources: {', '.join(sum_resources.values())}\n"
        query_text += "What malicious actions could an attacker perform with them to escalate privileges (escalate to another user, group or managed identity/role/service account or get more permissions somehow inside the cloud or inside the cloud service), access sensitive information from the could (env vars, connection strings, secrets, dumping buckets or disks... any kind of data storage)?"
        if any(perm.startswith("-") for perm in permissions):
            query_text += "Note that permissions starting with '-' are deny permissions.\n"
        query_text += self.malicious_actions_response_format

        result = self.query_hacktricks_ai(query_text)
        final_result = []

        if not result:
            return []
        
        # Re-check response to ensure it's correct and avoid false positives
        query_text = "### Context\n"
        query_text = f"You have been asked previously to provide the malicious actions that could be performed with the following {self.cloud_provider} permissions: {', '.join(permissions)}\n\n"
        query_text += "### Your response was:\n"
        query_text += json.dumps(result, indent=2)
        query_text += "\n\n### Indications\n"
        query_text += "- Check the response to ensure it's correct and avoid false positives.\n"
        query_text += "- Your new response should only contain valid potential attacks based on the given permissions and not attacks not related to the permissions.\n"
        query_text += "- Answer with a new JSON keeping the valid attacks, removing the false positives if any, and adding more attacks if someone was missed.\n"
        query_text += "- If no malicious actions are found, please provide an empty JSON array: []\n"
        query_text += self.malicious_actions_response_format
        result = self.query_hacktricks_ai(query_text)

        for entry in result:
            if not all(key in entry for key in ["Title", "Description", "Commands"]):
                print("Malformed response from Hacktricks AI: {}".format(entry))
            else:
                final_result.append({
                    "title": entry["Title"],
                    "description": entry["Description"],
                    "commands": entry["Commands"]
                })

        return final_result
    
    def analyze_sensitive_combinations_ai(self, permissions):
        query_text = f"Given the following {self.cloud_provider} permissions: {', '.join(permissions)}\n"
        query_text += "Indicate if any of those permissions are very sensitive or sensitive permissions. A very sensitive permission is a permission that allows to escalate privileges or read sensitive information that allows to escalate privileges like credentials or secrets. A sensitive permission is a permission that could be used to escalate privileges, read sensitive information or perform other cloud attacks, but it's not clear if it's enough by itself. A regular read permission that doesn't allow to read sensitive information (credentials, secrets, API keys...) is not sensitive.\n"
        query_text += "Note that permissions starting with '-' are deny permissions.\n"
        query_text += self.sensitive_response_format

        result = self.query_hacktricks_ai(query_text)
        final_result = {
            "very_sensitive_perms": [],
            "sensitive_perms": []
        }

        for entry in result:
            if not all(key in entry for key in ["permission", "is_very_sensitive", "is_sensitive", "description"]):
                print(f"Malformed response from Hacktricks AI: {entry}")
            else:
                if entry["is_very_sensitive"]:
                    final_result["very_sensitive_perms"].append(entry["permission"])
                elif entry["is_sensitive"]:
                    final_result["sensitive_perms"].append(entry["permission"])
                    
        return final_result



    def query_hacktricks_ai(self, msg, cont=0):
        """
        Query Hacktricks AI to analyze malicious actions for a message.

        Args:
            msg (str): Message to query Hacktricks AI.

        Returns:
            dict: Analysis result containing impact description or None if nothing found.
        """
        max_requests = 5
        window = 61  # seconds

        # Enforce global rate limit across threads
        while True:
            with self._rate_limit_lock:
                now = time.time()
                # Remove timestamps that are outside the 60-second window
                self._request_timestamps = [
                    t for t in self._request_timestamps if now - t < window
                ]
                if len(self._request_timestamps) < max_requests:
                    # Log the current request timestamp
                    self._request_timestamps.append(now)
                    break  # allowed to proceed
                else:
                    # Calculate wait time until the earliest timestamp exits the window
                    earliest = min(self._request_timestamps)
                    wait_time = window - (now - earliest)
            # Wait outside the lock to allow other threads to update
            time.sleep(wait_time)

        start_time = time.time()
        response = requests.post(HACKTRICKS_AI_ENDPOINT, json={"query": msg}, timeout=420)
        elapsed = time.time() - start_time

        if response.status_code != 200:
            print(f"{Fore.RED}Error querying Hacktricks AI: {response.status_code}, {response.text}")
            if cont < 3:
                print(f"{Fore.YELLOW}Trying again...")
                time.sleep(10)
                return self.query_hacktricks_ai(msg, cont=cont+1)
            return None

        try:
            result = response.json()
            result = result.get("response").strip()
            if result.startswith("```"):
                result = "\n".join(result.split("\n")[1:])
            if result.endswith("```"):
                result = "\n".join(result.split("\n")[:-1])
            result = json.loads(result)
        except Exception as e:
            print(f"{Fore.RED}Error parsing response from Hacktricks AI: {e}\nResponse: {response.text}")
            if cont < 3:
                print(f"{Fore.YELLOW}Trying again...")
                time.sleep(10)
                return self.query_hacktricks_ai(msg, cont=cont+1)
            return None

        return result

    def analyze_group(self, perms_set, resources_group):
        sensitive_perms = self.analyze_sensitive_combinations(perms_set)

        sensitive_perms_ai = {
            "very_sensitive_perms": [],
            "sensitive_perms": []
        } if self.not_use_ht_ai else self.analyze_sensitive_combinations_ai(perms_set)

        return {
            "permissions": list(perms_set),
            "resources": [r["id"] if "/" in r["id"] else r["id"] + ":" + r["type"] + ":" + r["name"] for r in resources_group],
            "sensitive_perms": sensitive_perms,
            "sensitive_perms_ai": sensitive_perms_ai
        }
    

    def process_combo(self, combo, all_very_sensitive_perms, all_sensitive_perms, all_very_sensitive_perms_ai, all_sensitive_perms_ai):
        perms = combo["permissions"]
        resources = combo["resources"]
        hacktricks_analysis = self.find_attacks_from_permissions(perms, resources)

        if not hacktricks_analysis:
            return None  # Skip if no analysis

        perms_msg = ""
        for perm in perms:
            if perm in all_very_sensitive_perms or perm in all_very_sensitive_perms_ai:
                perms_msg += f"{Fore.RED}{Back.YELLOW}{perm}{Style.RESET_ALL}, "
            elif perm in all_sensitive_perms or perm in all_sensitive_perms_ai:
                perms_msg += f"{Fore.RED}{perm}{Style.RESET_ALL}, "
            else:
                perms_msg += f"{Fore.WHITE}{perm}{Style.RESET_ALL}, "
        perms_msg = perms_msg.rstrip(", ")

        output_lines = [
            f"{Fore.YELLOW}\nPermissions: {perms_msg}"
        ]
        for attack in hacktricks_analysis:
            output_lines.extend([
                f"{Fore.BLUE}\nTitle: {Fore.WHITE}{attack['title']}",
                f"{Fore.BLUE}Description: {Fore.WHITE}{attack['description']}",
                f"{Fore.BLUE}Commands: {Fore.WHITE}{attack['commands']}\n"
            ])
        
        output_lines.append(Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)

        return "\n".join(output_lines)


    def run_analysis(self):
        print(f"{Fore.GREEN}\nStarting CloudPEASS analysis for {self.cloud_provider}...")
        print(f"{Fore.YELLOW}[{Fore.BLUE}i{Fore.YELLOW}] If you want to learn cloud hacking, check out the trainings at {Fore.CYAN}https://training.hacktricks.xyz")
        print(f"{Fore.MAGENTA}\nGetting information about your principal...")
        self.print_whoami_info()
        print(f"{Fore.MAGENTA}\nGetting all your permissions...")
        resources = self.get_resources_and_permissions()
        grouped_resources = self.group_resources_by_permissions(resources)
        all_very_sensitive_perms = set()
        all_sensitive_perms = set()
        all_very_sensitive_perms_ai = set()
        all_sensitive_perms_ai = set()

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
        print(f"{Fore.RED}  {Back.YELLOW}Very Sensitive Permissions{Style.RESET_ALL} - Permissions that allow to escalate privileges or read sensitive information that allows to escalate privileges like credentials or secrets.")
        print(f"{Fore.RED}  Sensitive Permissions{Style.RESET_ALL} - Permissions that could be used to escalate privileges, read sensitive information or perform other cloud attacks, but they aren't enough by themselves.")
        print(f"{Fore.WHITE}  Regular Permissions{Style.RESET_ALL} - Not so interesting permissions.")
        print()
        print()
        for result in analysis_results:
            perms = result["permissions"]
            sensitivity_ht = result["sensitive_perms"]
            sensitivity_ai = result["sensitive_perms_ai"]
            all_very_sensitive_perms.update(sensitivity_ht["very_sensitive_perms"])
            all_sensitive_perms.update(sensitivity_ht["sensitive_perms"])
            all_very_sensitive_perms_ai.update(sensitivity_ai["very_sensitive_perms"])
            all_sensitive_perms_ai.update(sensitivity_ai["sensitive_perms"])

            print(f"{Fore.WHITE}Resources: {Fore.CYAN}{f'{Fore.WHITE} , {Fore.CYAN}'.join(result['resources'])}")
            perms_msg = f"{Fore.WHITE}Permissions: "

            for perm in perms:
                if perm in sensitivity_ht["very_sensitive_perms"]:
                    perms_msg += f"{Fore.RED}{Back.YELLOW}{perm}{Style.RESET_ALL}, "
                
                elif perm in sensitivity_ai["very_sensitive_perms"]:
                    perms_msg += f"{Fore.RED}{Back.YELLOW}{perm}{Style.RESET_ALL}(AI), "
                
                elif perm in sensitivity_ht["sensitive_perms"]:
                    perms_msg += f"{Fore.RED}{perm}{Style.RESET_ALL}, "

                elif perm in sensitivity_ai["sensitive_perms"]:
                    perms_msg += f"{Fore.RED}{perm}{Style.RESET_ALL}(AI), "
                
                else:
                    perms_msg += f"{Fore.WHITE}{perm}{Style.RESET_ALL}, "
            
            perms_msg = perms_msg.strip()
            if perms_msg.endswith(","):
                perms_msg = perms_msg[:-1]
            perms_msg += Style.RESET_ALL
            
            print(perms_msg)
            print("\n" + Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)

        # Proceed with Hacktricks AI check if enabled
        if self.not_use_ht_ai:
            return
        
        print(f"{Fore.MAGENTA}\nQuerying Hacktricks AI for attacks, sit tight!")

        results = []
        with ThreadPoolExecutor(max_workers=min(self.num_threads, len(analysis_results))) as executor:
            futures = {
                executor.submit(self.process_combo, combo, all_very_sensitive_perms, all_sensitive_perms, all_very_sensitive_perms_ai, all_sensitive_perms_ai): combo
                for combo in analysis_results
            }

            for future in tqdm(as_completed(futures), total=len(futures), desc="Querying Hacktricks AI for attacks"):
                result = future.result()
                if result:
                    results.append(result)

        # Print aggregated results in a thread-safe manner
        for res in results:
            print(res)
        
        # Exit successfully
        print(f"{Fore.GREEN}\nAnalysis completed successfully!")
        exit(0)
