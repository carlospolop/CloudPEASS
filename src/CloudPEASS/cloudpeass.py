import json
import requests
from collections import defaultdict
from tqdm import tqdm
import time
import requests
import fnmatch


from colorama import Fore, Style, init, Back

init(autoreset=True)

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

If no malicious actions are found, please provide an empty JSON array: []
"""

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

    def get_resources_and_permissions(self):
        """
        Abstract method to collect resources and permissions. Must be implemented per cloud.

        Returns:
            list: List of resource dictionaries containing resource IDs, names, types, and permissions.
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
            grouped[perms_set].append(resource)
        return grouped

    def analyze_sensitive_combinations(self, permissions):
        found_very_sensitive = set()
        found_sensitive = set()

        # Check very sensitive combinations (with wildcard support)
        for combo in self.very_sensitive_combos:
            if all(any(fnmatch.fnmatch(perm, pattern) for perm in permissions) for pattern in combo):
                for pattern in combo:
                    for perm in permissions:
                        if fnmatch.fnmatch(perm, pattern):
                            found_very_sensitive.add(perm)

        # Check sensitive combinations (with wildcard support)
        for combo in self.sensitive_combos:
            if all(any(fnmatch.fnmatch(perm, pattern) for perm in permissions) for pattern in combo):
                for pattern in combo:
                    for perm in permissions:
                        if fnmatch.fnmatch(perm, pattern):
                            found_sensitive.add(perm)

        found_sensitive -= found_very_sensitive  # Avoid duplicates

        return {
            "very_sensitive_perms": found_very_sensitive,
            "sensitive_perms": found_sensitive
        }

    def find_attacks_from_permissions(self, permissions):
        """
        Query Hacktricks AI to analyze malicious actions for a set of permissions.

        Args:
            permissions (list): List of permission strings.
            cloud_provider (str): 'Azure', 'AWS', or 'GCP'.

        Returns:
            dict: Analysis result containing impact description or None if nothing found.
        """
        query_text = f"Given the following {self.cloud_provider} permissions: {', '.join(permissions)}\n"
        query_text += "What malicious actions could an attacker perform with them to for example escalate privileges (escalate to another user, group or managed identity/role/service account or get more permissions somehow inside the cloud or inside the cloud service), access sensitive information from the could (env vars, conneciton strings, secrets, dumping buckets or disks... any kind of data storage)?"
        query_text += self.malicious_actions_response_format

        result = self.query_hacktricks_ai(query_text)
        final_result = []

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
        query_text += "Indicate if any of those permissions are very sensitive or sensitive permissions. A very sensitive permision is a permission that allows to esalate privileges or read sensitive information for sure. A sensitive permission is a permission that could be used to escalate privileges or read sensitive information, but it's not clear if it's enough by itself. A regular read permission that doesn't allow to read sensitive information (credentials, secres, API keys...) is not sensitive."
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



    def query_hacktricks_ai(self, msg, cont=0, min_interval=12):
        """
        Query Hacktricks AI to analyze malicious actions for a message.

        Args:
            msg (str): Message to query Hacktricks AI.

        Returns:
            dict: Analysis result containing impact description or None if nothing found.
        """

        start_time = time.time()
        response = requests.post(HACKTRICKS_AI_ENDPOINT, json={"query": msg})
        elapsed = time.time() - start_time
        sleep_time = max(0, min_interval - elapsed) # Rate-limit (5 per min)
        time.sleep(sleep_time) 
        
        if response.status_code != 200:
            print(f"{Fore.RED}Error querying Hacktricks AI: {response.status_code}, {response.text}")
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
            print(f"{Fore.RED}Error parsing response from Hacktricks AI: {e}")
            if cont == 0:
                print(f"{Fore.YELLOW}Trying again...")
                time.sleep(10)
                return self.query_hacktricks_ai(msg, cont=1)
            return None

        return result

    def run_analysis(self):
        print(f"{Fore.MAGENTA}\nGetting all your permissions, sit tight!")
        resources = self.get_resources_and_permissions()
        grouped_resources = self.group_resources_by_permissions(resources)

        analysis_results = []
        for perms_set, resources_group in tqdm(grouped_resources.items(), desc="Analyzing Permissions"):
            sensitive_perms = self.analyze_sensitive_combinations(perms_set)
            
            if self.not_use_ht_ai:
                sensitive_perms_ai = {
                    "very_sensitive_perms": [],
                    "sensitive_perms": []
                }
            else:
                sensitive_perms_ai = self.analyze_sensitive_combinations_ai(perms_set)
            
            analysis_results.append({
                "permissions": list(perms_set),
                "resources": [r["id"] + ":" + r["type"] + ":" + r["name"] for r in resources_group],
                "sensitive_perms": sensitive_perms,
                "sensitive_perms_ai": sensitive_perms_ai
            })

        if self.out_path:
            with open(self.out_path, "w") as f:
                json.dump(analysis_results, f, indent=2)
            print(f"{Fore.GREEN}Results saved to {self.out_path}")

        # Clearly Print the results with the requested color formatting
        print(f"{Fore.YELLOW}\nDetailed Analysis Results:\n")
        for result in analysis_results:
            perms = result["permissions"]
            sensitivity_ht = result["sensitive_perms"]
            sensitivity_ai = result["sensitive_perms_ai"]

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
            
            print(perms_msg)
            print("\n" + Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)

        # Proceed with Hacktricks AI check if enabled
        if self.not_use_ht_ai:
            return
        
        print(f"{Fore.MAGENTA}\nQuerying Hacktricks AI for malicious actions...")
        for combo in tqdm(analysis_results, desc="Querying Hacktricks AI for attacks"):
            perms = combo["permissions"]
            hacktricks_analysis = self.find_attacks_from_permissions(perms)
            if hacktricks_analysis:
                # Prepare permissions colors
                perms_msg = ""
                for perm in perms:
                    if perm in sensitivity_ht["very_sensitive_perms"] or perm in sensitivity_ai["very_sensitive_perms"]:
                        perms_msg += f"{Fore.RED}{Back.YELLOW}{perm}{Style.RESET_ALL}, "
                    elif perm in sensitivity_ht["sensitive_perms"] or perm in sensitivity_ai["sensitive_perms"]:
                        perms_msg += f"{Fore.RED}{perm}{Style.RESET_ALL}, "
                    else:
                        perms_msg += f"{Fore.WHITE}{perm}{Style.RESET_ALL}, "
                perms_msg = perms_msg.strip()
                if perms_msg.endswith(","):
                    perms_msg = perms_msg[:-1]

                print(f"{Fore.YELLOW}\nPermissions: {', '.join(perms)}")
                for attack in hacktricks_analysis:
                    print(f"{Fore.BLUE}\nTitle: {Fore.WHITE}{attack['title']}")
                    print(f"{Fore.BLUE}Description: {Fore.WHITE}{attack['description']}")
                    print(f"{Fore.BLUE}Commands: {Fore.WHITE}{attack['commands']}\n")

