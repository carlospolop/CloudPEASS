import argparse
import boto3
import os
import json
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, init

init(autoreset=True)

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.sensitive_permissions.aws import very_sensitive_combinations, sensitive_combinations

AWS_MALICIOUS_RESPONSE_EXAMPLE = """[
    {
        "Title": "Privilege Escalation via Exploiting IAM Policies",
        "Description": "Using overly permissive IAM policies, an attacker might escalate privileges by performing unauthorized actions.",
        "Commands": "aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <action>"
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

class AWSPEASS(CloudPEASS):
    def __init__(self, aws_access_key_id, aws_secret_access_key, aws_session_token,
                 very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path=None):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.num_threads = num_threads

        # Initialize IAM and STS clients
        self.iam_client = boto3.client(
            'iam',
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token
        )
        self.sts_client = boto3.client(
            'sts',
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token
        )

        # Validate credentials by getting the caller identity
        self.principal_arn = self.get_caller_identity()
        self.principal_type, self.principal_name = self.parse_principal(self.principal_arn)
        
        super().__init__(very_sensitive_combos, sensitive_combos, "AWS", not_use_ht_ai, num_threads,
                         AWS_MALICIOUS_RESPONSE_EXAMPLE, AWS_SENSITIVE_RESPONSE_EXAMPLE, out_path)

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
        # ARN format examples:
        # - User: arn:aws:iam::123456789012:user/username
        # - Assumed Role: arn:aws:sts::123456789012:assumed-role/role-name/session-name
        arn_parts = arn.split(":")
        resource = arn_parts[-1]  # e.g. "user/username" or "assumed-role/role-name/session-name"
        parts = resource.split("/")
        if parts[0] == "user":
            return ("user", parts[1])
        elif parts[0] in ["assumed-role", "role"]:
            return ("role", parts[1])
        else:
            # Fallback to user if unknown format
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
        permissions = set()
        # Ensure policy_document is a dict
        if isinstance(policy_document, str):
            try:
                policy_document = json.loads(policy_document)
            except Exception as e:
                print(f"{Fore.RED}Error parsing policy document: {e}")
                return permissions
        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            # Process only Allow statements
            if stmt.get("Effect", "") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                permissions.add(actions)
            elif isinstance(actions, list):
                permissions.update(actions)
        return permissions

    def get_principal_permissions(self):
        """
        Retrieves permissions for the current principal (IAM user or role)
        by gathering attached and inline policies (and group policies in case of a user).
        """
        permissions = set()
        if self.principal_type == "user":
            # IAM User flow
            user_name = self.principal_name
            attached_policies = self.list_user_attached_policies(user_name)
            for policy in attached_policies:
                policy_arn = policy.get("PolicyArn")
                policy_versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                default_version = next((v for v in policy_versions.get("Versions", [])
                                        if v.get("IsDefaultVersion")), None)
                if default_version:
                    version_id = default_version.get("VersionId")
                    policy_doc_response = self.iam_client.get_policy_version(PolicyArn=policy_arn,
                                                                             VersionId=version_id)
                    policy_document = policy_doc_response.get("PolicyVersion", {}).get("Document", {})
                    permissions.update(self.extract_permissions(policy_document))
            inline_policies = self.list_user_inline_policies(user_name)
            for policy in inline_policies:
                policy_document = policy.get("PolicyDocument", {})
                permissions.update(self.extract_permissions(policy_document))
            groups = self.list_groups_for_user(user_name)
            for group in groups:
                group_name = group.get("GroupName")
                group_attached = self.list_group_attached_policies(group_name)
                for policy in group_attached:
                    policy_arn = policy.get("PolicyArn")
                    policy_versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                    default_version = next((v for v in policy_versions.get("Versions", [])
                                            if v.get("IsDefaultVersion")), None)
                    if default_version:
                        version_id = default_version.get("VersionId")
                        policy_doc_response = self.iam_client.get_policy_version(PolicyArn=policy_arn,
                                                                                 VersionId=version_id)
                        policy_document = policy_doc_response.get("PolicyVersion", {}).get("Document", {})
                        permissions.update(self.extract_permissions(policy_document))
                group_inline = self.list_group_inline_policies(group_name)
                for policy in group_inline:
                    policy_document = policy.get("PolicyDocument", {})
                    permissions.update(self.extract_permissions(policy_document))
        elif self.principal_type == "role":
            # IAM Role flow
            role_name = self.principal_name
            attached_policies = self.list_role_attached_policies(role_name)
            for policy in attached_policies:
                policy_arn = policy.get("PolicyArn")
                policy_versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                default_version = next((v for v in policy_versions.get("Versions", [])
                                        if v.get("IsDefaultVersion")), None)
                if default_version:
                    version_id = default_version.get("VersionId")
                    policy_doc_response = self.iam_client.get_policy_version(PolicyArn=policy_arn,
                                                                             VersionId=version_id)
                    policy_document = policy_doc_response.get("PolicyVersion", {}).get("Document", {})
                    permissions.update(self.extract_permissions(policy_document))
            inline_policies = self.list_role_inline_policies(role_name)
            for policy in inline_policies:
                policy_document = policy.get("PolicyDocument", {})
                permissions.update(self.extract_permissions(policy_document))
        return list(permissions)

    def get_resources_and_permissions(self):
        """
        Returns a list of resources and their permissions. For AWS,
        the resource is the principal (user or role) itself.
        """
        resources_data = []
        principal_permissions = self.get_principal_permissions()
        resources_data.append({
            "id": self.principal_arn,
            "name": self.principal_name,
            "type": "",
            "permissions": principal_permissions
        })
        return resources_data

if __name__ == "__main__":
    print("Not ready yet")
    exit(1)
    parser = argparse.ArgumentParser(
        description="Run AWSPEASS to find all your current permissions in AWS and check for potential privilege escalation risks.\n"
                    "AWSPEASS requires an id token (AWS Access Key ID), a secret token (AWS Secret Access Key) and optionally a role temp token (AWS Session Token)."
    )
    parser.add_argument('--aws-id-token', help="AWS Access Key ID")
    parser.add_argument('--aws-secret-token', help="AWS Secret Access Key")
    parser.add_argument('--aws-temp-token', default=None, help="AWS Session Token (optional)")
    parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/aws_results.json)")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_false", default=False, help="Don't use Hacktricks AI to analyze permissions")

    args = parser.parse_args()

    aws_id_token = args.aws_id_token or os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_token = args.aws_secret_token or os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_temp_token = args.aws_temp_token or os.getenv("AWS_SESSION_TOKEN")

    if not aws_id_token or not aws_secret_token:
        print(f"{Fore.RED}Both AWS Access Key ID and AWS Secret Access Key are required. Exiting.")
        exit(1)

    aws_peass = AWSPEASS(
        aws_id_token,
        aws_secret_token,
        aws_temp_token,
        very_sensitive_combinations,
        sensitive_combinations,
        not_use_ht_ai=args.not_use_hacktricks_ai,
        num_threads=args.threads,
        out_path=args.out_json_path
    )
    aws_peass.run_analysis()
