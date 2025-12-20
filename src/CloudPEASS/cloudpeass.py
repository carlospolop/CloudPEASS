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
import tiktoken
from pathlib import Path
import yaml
from typing import Optional


from colorama import Fore, Style, init, Back

init(autoreset=True)
faulthandler.enable()

HACKTRICKS_AI_ENDPOINT = "https://www.hacktricks.ai/api/ht-api"
PERMISSIONS_CATALOG_BASE_URL = "https://raw.githubusercontent.com/carlospolop/Blue-CloudPEASS/main"
PERMISSIONS_CATALOG_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days

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
Your response MUST be a valid JSON with the indicated format (an array of dicts with the keys "permission", "is_very_sensitive", "is_sensitive" and "description").
If no malicious actions are found, please provide an empty JSON array: []
__CLOUD_SPECIFIC_CLARIFICATIONS__

"""

MALICIOUS_ACTIONS_RESPONSE_FORMAT = """\n
### RESPONSE FORMAT

Your complete response must be a valid JSON with the following format:
[
    {
        "Title": "Malicious Action Title",
        "Description": "Description of the malicious action",
        "Commands": "Bash commands (using azure-cli, aws-cli, gcloud, etc.) to perform the malicious action",
        "Permissions": [
            "Permission 1",
            "Permission 2",
            ...
        ]
    },
    [...]
]

### EXAMPLE RESPONSE

__CLOUD_SPECIFIC_EXAMPLE__


### CLARIFICATIONS
- Remember to indicate as many malicious actions as possible (maximum 3) that can be performed with the given set of permissions, and provide the necessary commands to perform them.
- With a maximum of 3 techniques, prioritize privilege escalation and then sensitive information exfiltration techniques over deletion or DoS attacks.
- If more than one command is needed, just separate them with a newline character or a semi-colon inside the JSON field.
- Report only attacks whose most important permissions are assigned to the user and indicated. You can always suppose that the user has other necessary read, list or invoke permissions but not write permissions that haven't been indicated.
- Always recheck the response to ensure it's correct and avoid false positives.
- In the "Permissions" field indicate the most important permissions needed to perform each attack that the user has.
- Your response MUST be a valid JSON with the indicated format (an array of dicts with the keys "Title", "Description", "Commands" and "Permissions).
- If no malicious actions are found, please provide an empty JSON array as response: []
"""


def my_thread_excepthook(args):
    print(f"Exception in thread {args.thread.name}: {args.exc_type.__name__}: {args.exc_value}")
    # Start the post-mortem debugger session.
    pdb.post_mortem(args.exc_traceback)

threading.excepthook = my_thread_excepthook


class CloudPEASS:
    def __init__(self, very_sensitive_combos, sensitive_combos, cloud_provider, not_use_ht_ai, num_threads, example_malicious_cloud_response, example_sensitive_cloud_response, sensitive_perms_clarifications="", out_path=None):
        self.very_sensitive_combos = [set(combo) for combo in very_sensitive_combos]
        self.sensitive_combos = [set(combo) for combo in sensitive_combos]
        self.cloud_provider = cloud_provider
        self.not_use_ht_ai = not_use_ht_ai
        self.num_threads = int(num_threads)
        self.out_path = out_path
        self.malicious_actions_response_format = MALICIOUS_ACTIONS_RESPONSE_FORMAT.replace("__CLOUD_SPECIFIC_EXAMPLE__", example_malicious_cloud_response)
        self.sensitive_response_format = SENSITIVE_RESPONSE_FORMAT.replace("__CLOUD_SPECIFIC_EXAMPLE__", example_sensitive_cloud_response).replace("__CLOUD_SPECIFIC_CLARIFICATIONS__", sensitive_perms_clarifications)
        self._rate_limit_lock = threading.Lock()
        self._request_timestamps = []
        self._permissions_catalog = None
    
    def get_len_tokens(self, prompt) -> int:
        model="o3"
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(prompt))

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
            resources (list): List of resource dictionaries with permissions.

        Returns:
            dict: Keys as frozensets of permissions, values as lists of resources with those permissions.
        """

        # Group by affected resources first
        final_resources = {}
        for resource in resources:
            resource_id = resource["id"]
            resource_type = resource["type"]
            resource_name = resource["name"]
            if resource_id not in final_resources:
                final_resources[resource_id] = {
                    "id": resource_id,
                    "type": resource_type,
                    "name": resource_name,
                    "permissions": set()
                }
            final_resources[resource_id]["permissions"].update(resource["permissions"])


        grouped = defaultdict(list)
        for resource in final_resources.values():
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

    def _catalog_cloud_id(self) -> str:
        cloud = (self.cloud_provider or "").strip().lower()
        if cloud in {"aws", "azure", "gcp"}:
            return cloud
        raise ValueError("Unsupported cloud provider. Supported providers are: Azure, AWS, GCP.")

    def _catalog_cache_path(self) -> Path:
        cloud = self._catalog_cloud_id()
        filename = f"{cloud}_permissions_cat.yaml"
        return Path.home() / ".cache" / "cloudpeass" / "permissions_catalog" / filename

    def _should_refresh_catalog(self, path: Path) -> bool:
        if not path.exists():
            return True
        try:
            age_seconds = time.time() - path.stat().st_mtime
        except OSError:
            return True
        return age_seconds > PERMISSIONS_CATALOG_CACHE_TTL_SECONDS

    def _download_permissions_catalog(self) -> Optional[str]:
        cloud = self._catalog_cloud_id()
        url = f"{PERMISSIONS_CATALOG_BASE_URL}/{cloud}_permissions_cat.yaml"
        try:
            resp = requests.get(url, timeout=45)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Couldn't download permissions catalog: {e}")
            return None

        if resp.status_code != 200:
            print(f"{Fore.YELLOW}Warning: Couldn't download permissions catalog ({resp.status_code}): {resp.text[:200]}")
            return None
        return resp.text

    def _load_permissions_catalog(self) -> dict:
        if self._permissions_catalog is not None:
            return self._permissions_catalog

        cache_path = self._catalog_cache_path()
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        catalog_text = None
        if self._should_refresh_catalog(cache_path):
            catalog_text = self._download_permissions_catalog()
            if catalog_text:
                try:
                    cache_path.write_text(catalog_text, encoding="utf-8")
                except OSError:
                    pass

        if catalog_text is None and cache_path.exists():
            try:
                catalog_text = cache_path.read_text(encoding="utf-8")
            except OSError:
                catalog_text = None

        if not catalog_text:
            self._permissions_catalog = {"critical": set(), "high": set(), "medium": set(), "low": set()}
            return self._permissions_catalog

        try:
            parsed = yaml.safe_load(catalog_text) or {}
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Couldn't parse permissions catalog YAML: {e}")
            parsed = {}

        catalog = {}
        for level in ("critical", "high", "medium", "low"):
            values = parsed.get(level) or []
            if not isinstance(values, list):
                values = []
            catalog[level] = set(v for v in values if isinstance(v, str))

        self._permissions_catalog = catalog
        return self._permissions_catalog

    def categorize_permissions_from_catalog(self, permissions):
        catalog = self._load_permissions_catalog()
        categorized = {"critical": set(), "high": set(), "medium": set(), "low": set()}
        for perm in permissions or []:
            if not isinstance(perm, str) or perm.startswith("-"):
                continue
            if perm in catalog["critical"]:
                categorized["critical"].add(perm)
            elif perm in catalog["high"]:
                categorized["high"].add(perm)
            elif perm in catalog["medium"]:
                categorized["medium"].add(perm)
            elif perm in catalog["low"]:
                categorized["low"].add(perm)
        return categorized

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



    def find_attacks_from_permissions(self, analysis_results):
        """
        Query Hacktricks AI to get attacks based on the given permissions.

        Args:
            analysis_results (dict): Analysis results containing permissions and resources.

        Returns:
            dict: Analysis result containing impact description or None if nothing found.
        """

        query_text = "#### REQUEST\n"
        query_text += "What actions could an attacker perform with the following permissions to escalate privileges (escalate to another user, group or managed identity/role/service account or get more permissions somehow inside the cloud or inside the cloud service), access sensitive information from the could (env vars, connection strings, secrets, dumping buckets or disks... any kind of data storage)?"
        query_text += "\n\nNOTE: For safety and to minimize data shared, ONLY critical/high permissions are provided below. Medium/low/other permissions are NOT sent to HackTricks AI."
        query_text += "\n\n"

        query_text_perms = "#### IDENTIFIED PERMISSIONS\n"
        for result in analysis_results:
            # Get resources
            resources = result['resources']
            sum_resources = self.sumarize_resources(resources)
            if sum_resources:
                query_text_perms += f"Over the following resources: {', '.join(sum_resources.values())} these permissions were identified:\n"

            # Get permissions
            all_very_sensitive_perms = set()
            all_sensitive_perms = set()
            perms_cat = result.get("permissions_cat") or {}
            critical = sorted(set(perms_cat.get("critical") or []))
            high = sorted(set(perms_cat.get("high") or []))

            all_very_sensitive_perms.update(critical)
            all_sensitive_perms.update(high)

            if all_very_sensitive_perms:
                query_text_perms += f"- Critical permissions: {', '.join(sorted(all_very_sensitive_perms))}\n"
            if all_sensitive_perms:
                query_text_perms += f"- High permissions: {', '.join(sorted(all_sensitive_perms))}\n"

            if any(perm.startswith("-") for perm in list(all_sensitive_perms) + list(all_very_sensitive_perms)):
                query_text_perms += "- Note that permissions starting with '-' are deny permissions.\n"
            
            query_text_perms += "\n\n"
        
        query_text += query_text_perms
        query_text += self.malicious_actions_response_format

        result = self.query_hacktricks_ai(query_text)
        final_results = []

        if not result:
            return []
        
        # Re-check response to ensure it's correct and avoid false positives
        query_text = "### Context\n"
        query_text = f"You have been asked previously to provide the malicious actions that could be performed with the following {self.cloud_provider} permissions:\n\n"
        query_text += query_text_perms
        query_text += "### Your response was:\n"
        query_text += json.dumps(result, indent=2)
        query_text += "\n\n### Indications\n"
        query_text += "- Check the given response to ensure it's correct and remove false positives.\n"
        query_text += "- Your new response should only contain valid potential attacks based on the given permissions.\n"
        query_text += "- Report only attacks whose most important permissions are assigned to the user and indicated. You can always suppose that the user has other read, list or invoke permissions that are not indicated here, but all the write permissions have been indicated.\n"
        query_text += "- If a reported attack uses write or sensitive permissions that the user doesn't have (not indicated), it's a false possitive.\n"
        query_text += "- If the mentioned permissions for an attack are wrong, re-evaluate it.\n"
        query_text += "- Answer with a new JSON keeping the valid attacks, removing the false positives if any, and adding more attacks if anyone was missed.\n"
        query_text += "- If no malicious actions are found, please provide an empty JSON array as your reponse: []\n"
        query_text += self.malicious_actions_response_format
        result = self.query_hacktricks_ai(query_text)

        for entry in result:
            if not all(key in entry for key in ["Title", "Description", "Commands"]):
                print("Malformed response from Hacktricks AI: {}".format(entry))
            else:
                final_results.append({
                    "title": entry["Title"],
                    "description": entry["Description"],
                    "commands": entry["Commands"],
                    "permissions": entry["Permissions"]
                })

        return final_results
    
    def analyze_sensitive_combinations_ai(self, permissions):
        if not permissions:
            return {
                "very_sensitive_perms": [],
                "sensitive_perms": []
            }
        
        # Split permissions into chunks based on token count
        chunks = []
        current_chunk = []
        max_tokens_per_chunk = 30000

        # Process permissions in batches of 100
        batch_size = 100
        permissions_list = list(permissions)
        for i in range(0, len(permissions_list), batch_size):
            batch = permissions_list[i:i + batch_size]
            
            # Check if adding this batch would exceed token limit
            test_tokens = self.get_len_tokens(', '.join(current_chunk + batch))
            
            if test_tokens > max_tokens_per_chunk and current_chunk:
                # Current chunk is full, start a new one with this batch
                chunks.append(current_chunk)
                current_chunk = batch
            else:
                # Add the batch to current chunk
                current_chunk.extend(batch)
        
        # Add the last chunk if it has permissions
        if current_chunk:
            chunks.append(current_chunk)
        
        # Limit to first 5 chunks
        if len(chunks) > 5:
            print(f"{Fore.YELLOW}Warning: Too many permissions ({len(chunks)} chunks). Only analyzing the first 5 chunks of permissions.")
            chunks = chunks[:5]
        
        final_result = {
            "very_sensitive_perms": [],
            "sensitive_perms": []
        }
        
        # Process each chunk
        for i, chunk in enumerate(chunks):
            print(f"{Fore.WHITE}Analyzing permission chunk {i+1}/{len(chunks)} with AI ({len(chunk)} permissions)...")
            
            query_text = f"Given the following {self.cloud_provider} permissions: {', '.join(chunk)}\n"
            query_text += "Indicate if any of those permissions are very sensitive or sensitive permissions. A very sensitive permission is a permission that allows to escalate privileges or read sensitive information that allows to escalate privileges like credentials or secrets. A sensitive permission is a permission that could be used to escalate privileges, read sensitive information or perform other cloud attacks, but it's not clear if it's enough by itself. A regular read permission that doesn't allow to read sensitive information (credentials, secrets, API keys...) is not sensitive.\n"
            query_text += "Note that permissions starting with '-' are deny permissions.\n"
            query_text += self.sensitive_response_format
            
            result = self.query_hacktricks_ai(query_text)
            
            if result:
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
        try:
            response = requests.post(HACKTRICKS_AI_ENDPOINT, json={"query": msg}, timeout=420)
        except requests.exceptions.ConnectionError as e:
            if "429" in str(e):
                print(f"{Fore.RED}Error connecting to Hacktricks AI: {e}")
                print(f"{Fore.YELLOW}Rate limit exceeded. Retrying in 60 seconds...")
                time.sleep(60)
                return self.query_hacktricks_ai(msg, cont=cont+1)
            
            else:
                print(f"{Fore.RED}Error connecting to Hacktricks AI: {e}")
                
            if cont < 3:
                print(f"{Fore.YELLOW}Trying again...")
                time.sleep(10)
                return self.query_hacktricks_ai(msg, cont=cont+1)
            return None
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
                if cont > 0:
                    print(f"{Fore.YELLOW}Trying again...")
                time.sleep(5)
                msg += f"\n\n### Indications\n- You gave an wrongly formatted response. Fix the response so the format is like the expected JSON indicated.\n- Your invalid response was:\n\n{response.text}\n\n"
                return self.query_hacktricks_ai(msg, cont=cont+1)
            return None

        return result

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

        return {
            "permissions": list(perms_set),
            "resources": [r["id"] if "/" in r["id"] else r["id"] + ":" + r["type"] + ":" + r["name"] for r in resources_group],
            "sensitive_perms": sensitive_perms_serializable,
            "permissions_cat": {k: sorted(v) for k, v in perms_catalog.items()}
        }
    

    def run_analysis(self):
        print(f"{Fore.GREEN}\nStarting CloudPEASS analysis for {self.cloud_provider}...")
        print(f"{Fore.YELLOW}[{Fore.BLUE}i{Fore.YELLOW}] If you want to learn cloud hacking, check out the trainings at {Fore.CYAN}https://training.hacktricks.xyz")
        
        print(f"{Fore.MAGENTA}\nGetting information about your principal...")
        self.print_whoami_info()
        
        print(f"{Fore.MAGENTA}\nGetting all your permissions...")
        resources = self.get_resources_and_permissions()
        final_resources = []
        for resource in resources:
            if resource["permissions"]:
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
            perms_msg = f"{Fore.WHITE}Permissions: "

            for perm in perms:
                if perm in critical:
                    perms_msg += f"{Fore.RED}{Back.YELLOW}{perm}{Style.RESET_ALL}, "
                
                elif perm in high:
                    perms_msg += f"{Fore.RED}{perm}{Style.RESET_ALL}, "

                elif perm in medium:
                    perms_msg += f"{Fore.YELLOW}{perm}{Style.RESET_ALL}, "
                
                else:
                    perms_msg += f"{Fore.WHITE}{perm}{Style.RESET_ALL}, "
            
            perms_msg = perms_msg.strip()
            if perms_msg.endswith(","):
                perms_msg = perms_msg[:-1]
            perms_msg += Style.RESET_ALL
            
            print(perms_msg)
            print("\n" + Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)

        if not analysis_results:
            print(f"{Fore.RED}No permissions found. Exiting.")

        # Proceed with Hacktricks AI check if enabled
        elif self.not_use_ht_ai:
            print(f"{Fore.YELLOW}Hacktricks AI analysis disabled. Skipping Hacktricks AI recommendations.")
        
        else:

            print(f"{Fore.MAGENTA}\nQuerying Hacktricks AI for attacks, sit tight!")

            hacktricks_analysis = self.find_attacks_from_permissions(analysis_results)

            if not hacktricks_analysis:
                print(f"{Fore.YELLOW}No attacks found for the given permissions.")

            else:
                print(f"{Fore.YELLOW}\n" + "="*80)
                print(f"{Fore.YELLOW}⚠️  WARNING: The following attack vectors are AI-GENERATED suggestions.")
                print(f"{Fore.YELLOW}They may contain inaccuracies, hallucinations, or false positives.")
                print(f"{Fore.YELLOW}Always verify the information and test commands carefully before use.")
                print(f"{Fore.YELLOW}" + "="*80 + f"{Style.RESET_ALL}\n")
                for attack in hacktricks_analysis:
                    print(f"{Fore.BLUE}\nTitle: {Fore.WHITE}{attack['title']}")
                    print(f"{Fore.BLUE}Description: {Fore.WHITE}{attack['description']}")
                    print(f"{Fore.BLUE}Permissions: {Fore.WHITE}{', '.join(attack['permissions'])}")
                    print(f"{Fore.BLUE}Commands: {Fore.WHITE}{attack['commands']}\n")
                    # Append to output lines for later printing
                    print(Fore.LIGHTWHITE_EX + "-" * 80 + "\n" + Style.RESET_ALL)
                
        
        # Exit successfully
        print(f"{Fore.GREEN}\nAnalysis completed successfully!")
        print()
        print(f"{Fore.YELLOW}If you want to learn more about cloud hacking, check out the trainings at {Fore.CYAN}https://training.hacktricks.xyz")
        exit(0)
