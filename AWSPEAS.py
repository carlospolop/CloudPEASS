import argparse
import boto3
import os
import json
import time
import requests  # Needed for downloading AWS permissions for simulation
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, init
import re
import math
import subprocess
import base64
import binascii

init(autoreset=True)

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.sensitive_permissions.aws import very_sensitive_combinations, sensitive_combinations
from src.aws.awsbruteforce import AWSBruteForce
from src.aws.awsmanagedpoliciesguesser import AWSManagedPoliciesGuesser

AWS_MALICIOUS_RESPONSE_EXAMPLE = """[
    {
        "Title": "Privilege Escalation via Lambda functions code modification",
        "Description": "The attacker could create an AWS Lambda functions with a malicious code and then use the permissions of the assigned role to the function function to access other AWS services stealing its token from the metadata.",
        "Commands": "aws lambda create-function --function-name my_function \
    --runtime python3.8 --role <arn_of_lambda_role> \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://rev.zip",
        "Permissions": [
            "lambda:CreateFunction",
            "iam:PassRole"
        ],
    },
    [...]
]"""

AWS_SENSITIVE_RESPONSE_EXAMPLE = """[
    {
        "permission": "iam:PassRole",
        "is_very_sensitive": true,
        "is_sensitive": false,
        "description": "Allows passing a role to an AWS service, which can lead to privilege escalation if misconfigured."
    },
    [...]
]"""

AWS_CLARIFICATIONS = ""

class AWSPEASS(CloudPEASS):
    def __init__(self, profile_name, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, debug, region, aws_services, skip_iam_policies=False, skip_simulation=False, force_bruteforce=False, skip_managed_policies_guess=False, out_path=None):
        self.profile_name = profile_name
        self.num_threads = num_threads
        self.region = region
        self.skip_iam_policies = skip_iam_policies
        self.skip_simulation = skip_simulation
        self.force_bruteforce = force_bruteforce
        self.skip_managed_policies_guess = skip_managed_policies_guess

        # Initialize session using the profile
        self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region)
        self.credentials = self.session.get_credentials()

        # Initialize AWSBruteForce using the profile and region
        self.AWSBruteForce = AWSBruteForce(debug, self.region, self.profile_name, aws_services, self.num_threads)

        # Create IAM and STS clients from the session
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')

        # Validate credentials by getting the caller identity
        self.principal_arn = self.get_caller_identity()
        self.principal_type, self.principal_name = self.parse_principal(self.principal_arn)

        super().__init__(very_sensitive_combos, sensitive_combos, "AWS", not_use_ht_ai, num_threads,
                         AWS_MALICIOUS_RESPONSE_EXAMPLE, AWS_SENSITIVE_RESPONSE_EXAMPLE, AWS_CLARIFICATIONS, out_path)

    def get_caller_identity(self):
        try:
            identity = self.sts_client.get_caller_identity()
            return identity.get("Arn")
        except Exception as e:
            print(f"{Fore.RED}Invalid AWS credentials: {e}")
            exit(1)

    def parse_principal(self, arn):
        """
        Parses the principal ARN to determine if it's an IAM user or role.
        Returns a tuple: (principal_type, principal_name)
        """
        arn_parts = arn.split(":")
        resource = arn_parts[-1]  # e.g. "user/username" or "assumed-role/role-name/session-name"
        parts = resource.split("/")
        if parts[0] == "user":
            return ("user", parts[1])
        elif parts[0] in ["assumed-role", "role"]:
            return ("role", parts[1])
        else:
            return ("user", parts[-1])

    # User-specific methods
    def list_user_attached_policies(self, user_name):
        policies = []
        try:
            response = self.iam_client.list_attached_user_policies(UserName=user_name)
            policies.extend(response.get("AttachedPolicies", []))
        except Exception as e:
            print(f"{Fore.RED}Error listing attached policies for user {user_name}: {e}")
        return policies

    def list_user_inline_policies(self, user_name):
        policies = []
        try:
            response = self.iam_client.list_user_policies(UserName=user_name)
            policy_names = response.get("PolicyNames", [])
            for policy_name in policy_names:
                policy = self.iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policies.append({
                    "PolicyName": policy_name,
                    "PolicyDocument": policy.get("PolicyDocument", {})
                })
        except Exception as e:
            print(f"{Fore.RED}Error listing inline policies for user {user_name}: {e}")
        return policies

    def list_groups_for_user(self, user_name):
        groups = []
        try:
            response = self.iam_client.list_groups_for_user(UserName=user_name)
            groups = response.get("Groups", [])
        except Exception as e:
            print(f"{Fore.RED}Error listing groups for user {user_name}: {e}")
        return groups

    def list_group_attached_policies(self, group_name):
        policies = []
        try:
            response = self.iam_client.list_attached_group_policies(GroupName=group_name)
            policies.extend(response.get("AttachedPolicies", []))
        except Exception as e:
            print(f"{Fore.RED}Error listing attached policies for group {group_name}: {e}")
        return policies

    def list_group_inline_policies(self, group_name):
        policies = []
        try:
            response = self.iam_client.list_group_policies(GroupName=group_name)
            policy_names = response.get("PolicyNames", [])
            for policy_name in policy_names:
                policy = self.iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                policies.append({
                    "PolicyName": policy_name,
                    "PolicyDocument": policy.get("PolicyDocument", {})
                })
        except Exception as e:
            print(f"{Fore.RED}Error listing inline policies for group {group_name}: {e}")
        return policies

    # Role-specific methods
    def list_role_attached_policies(self, role_name):
        policies = []
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            policies.extend(response.get("AttachedPolicies", []))
        except Exception as e:
            print(f"{Fore.RED}Error listing attached policies for role {role_name}: {e}")
        return policies

    def list_role_inline_policies(self, role_name):
        policies = []
        try:
            response = self.iam_client.list_role_policies(RoleName=role_name)
            policy_names = response.get("PolicyNames", [])
            for policy_name in policy_names:
                policy = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                policies.append({
                    "PolicyName": policy_name,
                    "PolicyDocument": policy.get("PolicyDocument", {})
                })
        except Exception as e:
            print(f"{Fore.RED}Error listing inline policies for role {role_name}: {e}")
        return policies
    
    def extract_permissions(self, policy_document):
        """
        Extracts allowed permissions from a policy document.
        Checks for statements where "Effect" is "Allow" and returns the actions.
        """
        allowed = set()
        for statement in policy_document.get("Statement", []):
            if isinstance(statement, dict) and statement.get("Effect") == "Allow":
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                allowed.update(actions)
        return allowed

    def extract_denied_permissions(self, policy_document):
        """
        Extracts denied permissions from a policy document.
        Checks for statements where "Effect" is "Deny" and returns the actions.
        """
        denied = set()
        for statement in policy_document.get("Statement", []):
            if isinstance(statement, dict) and statement.get("Effect") == "Deny":
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                denied.update(actions)
        return denied

    def get_principal_permissions(self):
        """
        Retrieves allowed and denied permissions for the current principal (IAM user or role)
        by gathering attached and inline policies (and group policies in case of a user).
        Returns a dictionary with keys:
        - "allow": list of allowed permissions
        - "deny": list of denied permissions
        """
        allow_permissions = set()
        deny_permissions = set()
        
        if self.principal_type == "user":
            user_name = self.principal_name
            try:
                attached_policies = self.list_user_attached_policies(user_name)
            except Exception as e:
                print(f"{Fore.RED}Error listing attached policies for user {user_name}: {e}")
                attached_policies = []
            
            for policy in attached_policies:
                policy_arn = policy.get("PolicyArn")
                try:
                    policy_versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                except Exception as e:
                    print(f"{Fore.RED}Error listing policy versions for {policy_arn}: {e}")
                    policy_versions = {}

                default_version = next(
                    (v for v in policy_versions.get("Versions", []) if v.get("IsDefaultVersion")), 
                    None
                )
                if default_version:
                    version_id = default_version.get("VersionId")
                    try:
                        policy_doc_response = self.iam_client.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )
                    except Exception as e:
                        print(f"{Fore.RED}Error getting policy version {version_id} for {policy_arn}: {e}")
                        policy_doc_response = {}

                    policy_document = policy_doc_response.get("PolicyVersion", {}).get("Document", {})
                    allow_permissions.update(self.extract_permissions(policy_document))
                    deny_permissions.update(self.extract_denied_permissions(policy_document))
                    
            try:
                inline_policies = self.list_user_inline_policies(user_name)
            except Exception as e:
                print(f"{Fore.RED}Error listing inline policies for user {user_name}: {e}")
                inline_policies = []

            for policy in inline_policies:
                policy_document = policy.get("PolicyDocument", {})
                allow_permissions.update(self.extract_permissions(policy_document))
                deny_permissions.update(self.extract_denied_permissions(policy_document))
            
            try:
                groups = self.list_groups_for_user(user_name)
            except Exception as e:
                print(f"{Fore.RED}Error listing groups for user {user_name}: {e}")
                groups = []

            for group in groups:
                group_name = group.get("GroupName")
                try:
                    group_attached = self.list_group_attached_policies(group_name)
                except Exception as e:
                    print(f"{Fore.RED}Error listing attached policies for group {group_name}: {e}")
                    group_attached = []

                for policy in group_attached:
                    policy_arn = policy.get("PolicyArn")
                    try:
                        policy_versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                    except Exception as e:
                        print(f"{Fore.RED}Error listing policy versions for {policy_arn}: {e}")
                        policy_versions = {}

                    default_version = next(
                        (v for v in policy_versions.get("Versions", []) if v.get("IsDefaultVersion")), 
                        None
                    )
                    if default_version:
                        version_id = default_version.get("VersionId")
                        policy_doc_response = self.iam_client.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )
                        policy_document = policy_doc_response.get("PolicyVersion", {}).get("Document", {})
                        allow_permissions.update(self.extract_permissions(policy_document))
                        deny_permissions.update(self.extract_denied_permissions(policy_document))
                
                try:
                    group_inline = self.list_group_inline_policies(group_name)
                except Exception as e:
                    print(f"{Fore.RED}Error listing inline policies for group {group_name}: {e}")
                    group_inline = []

                for policy in group_inline:
                    policy_document = policy.get("PolicyDocument", {})
                    allow_permissions.update(self.extract_permissions(policy_document))
                    deny_permissions.update(self.extract_denied_permissions(policy_document))
        
        elif self.principal_type == "role":
            role_name = self.principal_name
            try:
                attached_policies = self.list_role_attached_policies(role_name)
            except Exception as e:
                print(f"{Fore.RED}Error listing attached policies for role {role_name}: {e}")
                attached_policies = []

            for policy in attached_policies:
                policy_arn = policy.get("PolicyArn")
                try:
                    policy_versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                except Exception as e:
                    print(f"{Fore.RED}Error listing policy versions for {policy_arn}: {e}")
                    policy_versions = {}

                default_version = next(
                    (v for v in policy_versions.get("Versions", []) if v.get("IsDefaultVersion")), 
                    None
                )
                if default_version:
                    version_id = default_version.get("VersionId")
                    policy_doc_response = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    policy_document = policy_doc_response.get("PolicyVersion", {}).get("Document", {})
                    allow_permissions.update(self.extract_permissions(policy_document))
                    deny_permissions.update(self.extract_denied_permissions(policy_document))
            
            try:
                inline_policies = self.list_role_inline_policies(role_name)
            except Exception as e:
                print(f"{Fore.RED}Error listing inline policies for role {role_name}: {e}")
                inline_policies = []

            for policy in inline_policies:
                policy_document = policy.get("PolicyDocument", {})
                allow_permissions.update(self.extract_permissions(policy_document))
                deny_permissions.update(self.extract_denied_permissions(policy_document))
        
        return {
            "allow": list(allow_permissions),
            "deny": list(deny_permissions)
        }

    # New method: Download AWS permissions from the Policy Generator
    def download_aws_permissions(self) -> dict:
        url = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
        response = requests.get(url)
        if response.status_code != 200:
            print(f"{Fore.RED}Error: Unable to fetch AWS policies from the Policy Generator.")
            return {}
        # Remove the prefix to get valid JSON
        resp_text = response.text.replace("app.PolicyEditorConfig=", "")
        policies = json.loads(resp_text)
        permissions = {}
        for service in policies["serviceMap"]:
            service_name = policies["serviceMap"][service]["StringPrefix"]
            actions = policies["serviceMap"][service]["Actions"]
            permissions[service_name] = actions
        return permissions

    def simulate_batch(self, actions: list) -> set:
        allowed = set()
        try:
            response = self.iam_client.simulate_principal_policy(
                PolicySourceArn=self.principal_arn, ActionNames=actions
            )
            for result in response.get("EvaluationResults", []):
                if result.get("EvalDecision").lower() == "allowed":
                    allowed.add(result.get("EvalActionName"))
        except Exception as e:
            if "rate exceeded" in str(e).lower():
                print(f"{Fore.RED}Rate limit exceeded. Waiting for 25 seconds...")
                time.sleep(25)
                return self.simulate_batch(actions)
            print(f"{Fore.RED}Error simulating batch: {e}")
        return allowed

    def simulate_permissions(self, batch_size: int = 50) -> list:
        # Check if the user has permission to simulate by making a test API call
        try:
            test_response = self.iam_client.simulate_principal_policy(
                PolicySourceArn=self.principal_arn, ActionNames=["iam:ListUsers"]
            )
        except Exception as e:
            print(f"{Fore.RED}User does not have permission to simulate permissions via simulate_principal_policy API: {e}")
            return []

        aws_permissions = self.download_aws_permissions()
        if not aws_permissions:
            return []

        print(f"{Fore.GREEN}Simulating principal policy permissions using simulate_principal_policy API...")

        # Prepare all actions in the format service:action
        action_batches = [f"{service}:{action}" for service, actions in aws_permissions.items() for action in actions]
        batches = [action_batches[i:i + batch_size] for i in range(0, len(action_batches), batch_size)]
        simulated_permissions = set()

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(self.simulate_batch, batch) for batch in batches]
            pbar = tqdm(total=len(futures), desc="Simulating batches")
            for future in as_completed(futures):
                simulated_permissions.update(future.result())
                pbar.update(1)
            pbar.close()
        return list(simulated_permissions)
    
    def shannon_entropy(self, s):
        """
        Calculate the Shannon entropy of a string.
        """
        frequencies = {}
        for char in s:
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        for freq in frequencies.values():
            p = freq / len(s)
            entropy -= p * math.log(p, 2)
        return entropy
    
    def is_canary_user(self, arn, name):
        """
        Checks if the current principal is a canary user.
        A canary user is an IAM user with a specific name pattern.
        """

        reason = ""
        is_canary = False

        # Check if the principal name contains any canary names
        if any(acc_id in arn for acc_id in ["534261010715", "717712589309", "266735846894"]):
            reason = "Canary AWS account detected. Probability: High."
            is_canary = True
        
        # Check if the principal name contains any canary names
        elif any(canary_names in arn.lower() for canary_names in ["canarytokens", "spacecrab", "canary", "spacesiren", ]):
            reason = "Canary name detected. Probability: High."
            is_canary = True
        
        # Check if the name is a UUID
        elif len(name) == 36 and name.count("-") == 4:
            reason = "UUID detected. Probability: Medium."
            is_canary = True
            if re.match(r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}$", name):
                reason = "SpaceSiren UUID detected. Probability: High."

        # Check the entropy of the name
        elif len(name) >= 8:
            entropy_value = self.shannon_entropy(name)
            # Adjust the threshold as necessary.
            if entropy_value > 3.85:
                reason = "High entropy (random) name detected. Probability: Medium."
                is_canary = True        

        return is_canary, reason
    
    def get_identity_without_logs(self):
        """
        Retrieves the current principal's identity without logging it.
        This is useful for avoiding detection.
        """

        # NOT USED BECAUSE THIS NOW GENERATES LOGS ALSO ON THE AWS ACCOUNT OF THE USER

        arn = ""
        principal_name = ""
        principal_type = ""

        cmd = f"""aws sns publish --profile {self.profile_name} --topic-arn "arn:aws:sns:us-east-1:791397163361:AWSPEASSTopic" --message "Hello from AWSPEASS." --region us-east-1"""
        
        # Use awscli to call aws cli and get the arn of the principal from the error printed
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=20)
        output = result.stdout.decode() + result.stderr.decode()

        # Make sure we don't detect this
        output = output.replace("arn:aws:sns:us-east-1:791397163361:AWSPEASSTopic", "")

        if "arn:aws:iam::" in output.lower():
            # Extract the name from the error message
            match_user = re.search(r"arn:aws:iam::[0-9]{12}:user/([^ ]*) ", output)
            if match_user:
                arn = match_user.group(0)
                principal_name = match_user.group(1)
                principal_type = "user"
            
            match_role = re.search(r"arn:aws:iam::[0-9]{12}:(role|assumed-role)/([^ ]*) ", output)
            if match_role:
                arn = match_role.group(0)
                principal_name = match_role.group(2)
                principal_type = "role"
        
        else:
            print(f"{Fore.RED}Error: Unable to retrieve principal ARN without generating logs.")
        
        return arn, principal_name, principal_type
    
    def AWSAccount_from_AWSKeyID(self, AWSKeyID):
        # From https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
        trimmed_AWSKeyID = AWSKeyID[4:] #remove KeyID prefix
        x = base64.b32decode(trimmed_AWSKeyID) #base32 decode
        y = x[0:6]

        z = int.from_bytes(y, byteorder='big', signed=False)
        mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)

        e = (z & mask)>>7
        
        is_canary = False
        if e in [534261010715, 717712589309, 266735846894]:
            is_canary = True
        
        return e, is_canary
        
    
    def print_whoami_info(self):
        """
        Prints the current principal information (ARN, type, and name).
        This is useful for debugging and understanding the context of the permissions being analyzed.
        """
        
        try:
            acc_id, is_canary = self.AWSAccount_from_AWSKeyID(self.credentials.access_key.strip())
            if is_canary:
                print(f"\n{Fore.RED}It looks like the credentials could belong to a canary user based on the AWS account ID ({acc_id}).{Fore.RESET}")
                user_input = input(f"{Fore.RED}Do you want to continue? (y/N) {Fore.RESET}")
                if user_input.lower() != "y":
                    print(f"{Fore.RED}Exiting...")
                    exit(0)
            
            # If we couldn't get the principal ARN, use the STS client to get it
            identity = self.sts_client.get_caller_identity()
            principal_arn = identity.get("Arn")
            principal_type, principal_name = self.parse_principal(principal_arn)
            
            print(f"{Fore.BLUE}Current Principal ARN: {Fore.WHITE}{principal_arn}")
            print(f"{Fore.BLUE}Principal Type: {Fore.WHITE}{principal_type}")
            print(f"{Fore.BLUE}Principal Name: {Fore.WHITE}{principal_name}")

            # Check if the principal is a canary user
            is_canary, reason = self.is_canary_user(principal_arn, principal_name)
            print(f"{Fore.BLUE}Is Canary User: {Fore.WHITE}{is_canary}")
            if is_canary:
                print(f"{Fore.RED}Is Canary Reason: {Fore.WHITE}{reason}{Fore.RESET}")
                print(f"{Fore.RED}[!] {Fore.YELLOW}If this is a canary, you will probably trigger alerts in the company in less than 5mins...{Fore.RESET}")
                time.sleep(2)
                print(f"I will continue in the meantime...")
                
        
        except Exception as e:
            print(f"{Fore.RED}Error retrieving principal information: {e}")

    def get_resources_and_permissions(self):
        """
        Returns a list of resources and their permissions using different methods:
        - Try to read IAM policies
        - Try to simulate permissions using simulate-principal-policy
        - Brute-force permissions using AWSBruteForce
        - If BF is used, try to guess permissions based on AWS managed policies

        The resource object now includes:
        - "permissions": allowed permissions
        - "deny_perms": explicitly denied permissions
        """
        resources_data = []

        principal_perms = {"allow": [], "deny": []}
        
        # Try to get permissions from IAM policies
        if not self.skip_iam_policies:
            principal_perms = self.get_principal_permissions()
        else:
            print(f"{Fore.YELLOW}Skipping IAM policies retrieval (--skip-iam-policies flag set)")
        
        # Now try to brute-force permissions using simulate-principal-policy, if allowed
        simulated_permissions = []
        if not self.skip_simulation:
            simulated_permissions = aws_peass.simulate_permissions()
        else:
            print(f"{Fore.YELLOW}Skipping simulation of permissions (--skip-simulation flag set)")

        if simulated_permissions:
            principal_perms["allow"].extend(simulated_permissions)
        
        principal_perms["allow"] = list(set(principal_perms["allow"]))

        if "*" in principal_perms["allow"]:
            print(f"{Fore.GREEN}Principal has full access (*). You can do mostly everything. Skipping further analysis.")
            exit(0)
        
        resources_data.append({
            "id": "",
            "name": "",
            "type": "",
            "permissions": principal_perms["allow"],
            "deny_perms": principal_perms["deny"]
        })

        brute_force = False
        if self.force_bruteforce:
            print(f"{Fore.YELLOW}Forcing brute-force (--force-bruteforce flag set)")
            brute_force = True
        elif resources_data[0]["permissions"]:
            # Ask the user if he wants to brute-force permissions
            print(f"{Fore.GREEN}Found permissions for the principal.")
            brute_force_input = input(f"{Fore.YELLOW}Do you still want to brute-force permissions? (y/N) ")
            if brute_force_input.lower() == "y":
                brute_force = True
        else:
            print(f"{Fore.GREEN}No permissions found for the principal. Strating brute-force...")
            brute_force = True
        
        if brute_force:
            bf_permissions = self.AWSBruteForce.brute_force_permissions()
            if bf_permissions:
                resources_data.append(
                    {
                        "id": "",
                        "name": "",
                        "type": "",
                        "permissions": bf_permissions,
                        "deny_perms": []
                    }
                )
        
        if brute_force:
            if self.skip_managed_policies_guess:
                print(f"{Fore.YELLOW}Skipping managed policies guess (--skip-managed-policies-guess flag set){Fore.RESET}")
            else:
                guess_permissions = input(f"{Fore.YELLOW}Do you want to guess permissions based on AWS managed policies? (Y/n) {Fore.RESET}")
                if guess_permissions.lower() != "n":
                    guesser = AWSManagedPoliciesGuesser(set(bf_permissions))
                    guessed_perms = guesser.guess_permissions()

                    if guessed_perms:
                        print()
                        print("Color legend:")
                        print(f"{Fore.GREEN}  Green: Permissions that you already have{Fore.RESET}")
                        print(f"{Fore.BLUE}  Blue: Permissions that were guessed based on AWS managed policies{Fore.RESET}")
                        print()

                        # Show each combination and ask the user which one to add
                        all_coms = []
                        i = 0
                        for key, value in guessed_perms.items():
                            i += 1
                            print(f"{Fore.YELLOW}[{i}]{Fore.WHITE} This combination has {Fore.YELLOW}{key}{Fore.WHITE} permissions not detected.\n    {Fore.WHITE}Policies: {Fore.CYAN}{', '.join(value['policies'])}\n    {Fore.WHITE}Permissions: {Fore.BLUE}{', '.join([f'{Fore.GREEN}{perm}{Fore.BLUE}' if perm in bf_permissions else perm for perm in value['permissions']])}{Fore.RESET}")
                            all_coms.append(value['permissions'])
                            print()

                        # Ask the user which combination to add
                        selected_comb = False
                        selected_combination = -1
                        while not selected_comb:
                            selected_combination = input(f"{Fore.YELLOW}Select a combination to add those permissions to check from 1 to {i} (1 is the recommended one) or -1 to not add any: {Fore.RESET}")
                            selected_combination = int(selected_combination)
                            if selected_combination < -1 or selected_combination == 0 or selected_combination > i:
                                print(f"{Fore.RED}Invalid selection. Try again.{Fore.RESET}")
                            else:
                                selected_comb = True
                        
                        if selected_combination != -1:
                            selected_combination -= 1
                            resources_data.append(
                                {
                                    "id": "",
                                    "name": "",
                                    "type": "",
                                    "permissions": all_coms[selected_combination],
                                    "deny_perms": []
                                }
                            )
                    else:
                        print(f"{Fore.YELLOW}No managed policy combinations found.{Fore.RESET}")

        return resources_data

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Run AWSPEASS to find all your current permissions in AWS and check for potential privilege escalation risks.\n"
                    "AWSPEASS requires the name of the profile to use to connect to AWS."
    )
    parser.add_argument('--profile', required=True, help="AWS profile to use")
    parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/aws_results.json)")
    parser.add_argument('--threads', default=10, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_true", default=False, help="Don't use Hacktricks AI to suggest attack paths")
    parser.add_argument('--debug', default=False, action="store_true", help="Print more infromation when brute-forcing permissions")
    parser.add_argument('--region', required=True, help="Indicate the region to use for brute-forcing permissions")
    parser.add_argument('--aws-services', help="Filter AWS services to brute-force permissions for indicating them as a comma separated list (e.g. --aws-services s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb)")
    parser.add_argument('--skip-iam-policies', action="store_true", default=False, help="Skip retrieving permissions from IAM policies")
    parser.add_argument('--skip-simulation', action="store_true", default=False, help="Skip simulating permissions using simulate-principal-policy")
    parser.add_argument('--force-bruteforce', action="store_true", default=False, help="Force brute-force without asking")
    parser.add_argument('--skip-managed-policies-guess', action="store_true", default=False, help="Skip guessing permissions based on AWS managed policies")

    args = parser.parse_args()

    profile = args.profile or os.getenv("AWS_PROFILE")

    aws_services = args.aws_services.split(",") if args.aws_services else []

    aws_peass = AWSPEASS(
        profile,
        very_sensitive_combinations,
        sensitive_combinations,
        not_use_ht_ai=args.not_use_hacktricks_ai,
        num_threads=args.threads,
        debug=args.debug,
        region=args.region,
        aws_services=aws_services,
        skip_iam_policies=args.skip_iam_policies,
        skip_simulation=args.skip_simulation,
        force_bruteforce=args.force_bruteforce,
        skip_managed_policies_guess=args.skip_managed_policies_guess,
        out_path=args.out_json_path
    )
    # Run the analysis to get permissions from policies
    aws_peass.run_analysis()
