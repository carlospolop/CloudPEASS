import argparse
import base64
import binascii
import fnmatch
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from colorama import Back, Fore, Style, init
from tqdm import tqdm

from src.CloudPEASS.cloudpeass import CloudPEASS, CloudResource
from src.aws.awsbruteforce import AWSBruteForce
from src.aws.awsmanagedpoliciesguesser import AWSManagedPoliciesGuesser
from src.sensitive_permissions.aws import sensitive_combinations, very_sensitive_combinations


init(autoreset=True)

POLICY_GENERATOR_URL = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
MANAGED_POLICIES_URL = (
    "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/managed_policies.json"
)
AUTHORIZATION_ERRORS = {
    "AccessDenied",
    "AccessDeniedException",
    "AuthorizationError",
    "Forbidden",
    "UnauthorizedOperation",
    "UnrecognizedClientException",
}


class AWSPEASS(CloudPEASS):
    """Enumerate AWS permissions without making mutating or execution API calls."""

    def __init__(
        self,
        profile_name,
        very_sensitive_combos,
        sensitive_combos,
        num_threads,
        debug,
        region,
        aws_services,
        skip_iam_policies=False,
        skip_simulation=False,
        skip_bruteforce=False,
        skip_managed_policies_guess=False,
        out_path=None,
        access_key_id=None,
        secret_access_key=None,
        session_token=None,
        no_ask=False,
        bruteforce_always=False,
    ):
        # A typo such as --threads 10000 should not exhaust file descriptors or
        # overwhelm either the local host or AWS read-only APIs.
        safe_threads = max(1, min(int(num_threads), 64))
        super().__init__(very_sensitive_combos, sensitive_combos, "AWS", safe_threads, out_path)
        self.profile_name = profile_name
        self.debug = debug
        self.skip_iam_policies = skip_iam_policies
        self.skip_simulation = skip_simulation
        self.skip_bruteforce = skip_bruteforce
        self.skip_managed_policies_guess = skip_managed_policies_guess
        self.no_ask = no_ask
        self.bruteforce_always = bruteforce_always
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token

        session_args = {}
        if profile_name:
            session_args["profile_name"] = profile_name
        if access_key_id and secret_access_key:
            session_args.update(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                aws_session_token=session_token,
            )
        if region:
            session_args["region_name"] = region

        self.session = boto3.Session(**session_args)
        self.region = region or self.session.region_name or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        config = Config(
            connect_timeout=10,
            read_timeout=30,
            max_pool_connections=max(10, safe_threads * 2),
            retries={"mode": "adaptive", "max_attempts": 6},
        )
        self.iam_client = self.session.client("iam", config=config)
        self.sts_client = self.session.client("sts", region_name=self.region, config=config)

        credentials = self.session.get_credentials()
        if credentials is None:
            raise NoCredentialsError()
        self.credentials = credentials.get_frozen_credentials()

        self.identity = None
        self.principal_arn = None
        self.principal_type = None
        self.principal_name = None
        self.is_session_principal = False
        self.entity_arn = None
        self.permissions_boundary_arns = set()
        self.policy_conditions = set()
        self.policy_notes = []
        self.iam_errors = []
        self.iam_visibility = "not attempted"
        self.action_catalog = None
        self.action_catalog_source = None
        self.public_managed_policy_actions = None
        self.simulation_is_admin = False
        self.max_permissions_per_category = 50

        # Temporary credentials may expire during a broad probe, so keep their
        # profile refresh chain. Long-lived credentials can be passed directly,
        # avoiding repeated credential_process/profile startup in every child.
        cli_profile = profile_name if profile_name and self.credentials.token else None
        profiles = (
            self.session._session.full_config.get("profiles", {}) if cli_profile else {}
        )
        profile_uses_environment = self._profile_chain_uses_environment(
            profiles, cli_profile
        )
        self.AWSBruteForce = AWSBruteForce(
            debug,
            self.region,
            cli_profile,
            aws_services,
            self.num_threads,
            access_key_id or self.credentials.access_key,
            secret_access_key or self.credentials.secret_key,
            session_token or self.credentials.token,
            profile_uses_environment_credentials=profile_uses_environment,
        )

    @staticmethod
    def _profile_chain_uses_environment(profiles, profile_name):
        """Detect credential_source=Environment through source_profile chains."""
        seen = set()
        while isinstance(profile_name, str) and profile_name and profile_name not in seen:
            seen.add(profile_name)
            config = profiles.get(profile_name, {}) if isinstance(profiles, dict) else {}
            if not isinstance(config, dict):
                return False
            if str(config.get("credential_source", "")).casefold() == "environment":
                return True
            profile_name = config.get("source_profile")
        return False

    # Identity and credential safety
    def get_caller_identity(self):
        if self.identity is None:
            try:
                self.identity = self.sts_client.get_caller_identity()
            except (BotoCoreError, ClientError) as exc:
                raise RuntimeError(f"AWS credentials could not call STS GetCallerIdentity: {exc}") from exc
            self.principal_arn = self.identity.get("Arn", "")
            self.principal_type, self.principal_name = self.parse_principal(self.principal_arn)
            self.is_session_principal = ":sts::" in self.principal_arn and ":assumed-role/" in self.principal_arn
            if self.principal_type == "user" or ":iam::" in self.principal_arn:
                self.entity_arn = self.principal_arn
        return self.principal_arn

    @staticmethod
    def parse_principal(arn):
        """Return a stable IAM entity type/name for IAM, STS, root, and federated ARNs."""
        if not arn or ":" not in arn:
            return "unknown", arn or "unknown"
        resource = arn.split(":", 5)[-1]
        parts = resource.split("/")
        kind = parts[0]
        if kind == "user":
            return "user", parts[-1]
        if kind == "role":
            return "role", parts[-1]
        if kind == "assumed-role" and len(parts) >= 3:
            return "role", parts[-2]
        if kind == "federated-user":
            return "federated-user", "/".join(parts[1:])
        if resource == "root":
            return "root", "root"
        return kind or "unknown", parts[-1]

    @staticmethod
    def AWSAccount_from_AWSKeyID(aws_key_id):
        """Decode the account encoded in modern AKIA/ASIA access-key IDs."""
        if not isinstance(aws_key_id, str) or len(aws_key_id) != 20:
            return None, False
        if aws_key_id[:4] not in {"AKIA", "ASIA"}:
            return None, False
        try:
            raw = base64.b32decode(aws_key_id[4:])
            value = int.from_bytes(raw[0:6], byteorder="big", signed=False)
            mask = int.from_bytes(binascii.unhexlify(b"7fffffffff80"), byteorder="big", signed=False)
            account_id = (value & mask) >> 7
        except (ValueError, TypeError, binascii.Error):
            return None, False
        known_canaries = {534261010715, 717712589309, 266735846894}
        return account_id, account_id in known_canaries

    @staticmethod
    def shannon_entropy(value):
        if not value:
            return 0.0
        frequencies = {char: value.count(char) for char in set(value)}
        return -sum((count / len(value)) * math.log(count / len(value), 2) for count in frequencies.values())

    def is_canary_user(self, arn, name):
        known_accounts = ("534261010715", "717712589309", "266735846894")
        if any(account in arn for account in known_accounts):
            return True, "Known canary AWS account ID detected. Probability: high."
        if any(marker in arn.lower() for marker in ("canarytokens", "spacecrab", "canary", "spacesiren")):
            return True, "Canary-like principal name detected. Probability: high."
        uuid_v4 = r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
        if re.fullmatch(uuid_v4, name, re.I):
            return True, "SpaceSiren-like UUID detected. Probability: high."
        if len(name) == 36 and name.count("-") == 4:
            return True, "UUID-like principal name detected. Probability: medium."
        if len(name) >= 8 and self.shannon_entropy(name) > 3.85:
            return True, "High-entropy principal name detected. Probability: medium."
        return False, ""

    def _confirm_canary(self, account_id, reason):
        print(f"{Fore.RED}[!] Possible canary credentials: {reason}")
        if account_id:
            print(f"{Fore.RED}    Locally decoded account ID: {account_id}")
        if self.no_ask:
            print(f"{Fore.RED}Stopping because --no-ask uses the safe default for canary warnings.")
            raise SystemExit(2)
        if input(f"{Fore.RED}Continue and make read-only AWS API calls? (y/N): {Fore.RESET}").strip().lower() != "y":
            raise SystemExit(0)

    def print_whoami_info(self):
        decoded_account, key_is_canary = self.AWSAccount_from_AWSKeyID(self.credentials.access_key)
        if key_is_canary:
            self._confirm_canary(decoded_account, "the access-key encoding matches a known canary account")

        principal_arn = self.get_caller_identity()
        is_canary, reason = self.is_canary_user(principal_arn, self.principal_name)
        if is_canary and not key_is_canary:
            self._confirm_canary(self.identity.get("Account"), reason)

        whoami = {
            "cloud": "aws",
            "account_id": self.identity.get("Account"),
            "user_id": self.identity.get("UserId"),
            "arn": principal_arn,
            "principal_type": self.principal_type,
            "principal_name": self.principal_name,
            "region": self.region,
            "is_canary": is_canary or key_is_canary,
            "is_canary_reason": reason if is_canary else None,
        }
        print(f"{Fore.BLUE}Account ID: {Fore.WHITE}{whoami['account_id']}")
        print(f"{Fore.BLUE}Current Principal ARN: {Fore.WHITE}{principal_arn}")
        print(f"{Fore.BLUE}Principal Type: {Fore.WHITE}{self.principal_type}")
        print(f"{Fore.BLUE}Principal Name: {Fore.WHITE}{self.principal_name}")
        print(f"{Fore.BLUE}Region used for regional probes: {Fore.WHITE}{self.region}")
        print(f"{Fore.BLUE}Possible canary: {Fore.WHITE}{whoami['is_canary']}")
        return whoami

    # IAM read helpers and policy collection
    def _record_iam_error(self, operation, exc):
        code = "UnknownError"
        message = str(exc)
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", code)
            message = error.get("Message", message)
        self.iam_errors.append({"operation": operation, "code": code, "message": message})
        if self.debug:
            print(f"{Fore.YELLOW}[DEBUG] {operation} failed ({code}): {message}")

    def _call_iam(self, operation, **kwargs):
        try:
            return getattr(self.iam_client, operation)(**kwargs), True
        except (BotoCoreError, ClientError) as exc:
            self._record_iam_error(operation, exc)
            return {}, False

    def _paginate_iam(self, operation, result_key, **kwargs):
        try:
            if self.iam_client.can_paginate(operation):
                items = []
                for page in self.iam_client.get_paginator(operation).paginate(**kwargs):
                    items.extend(page.get(result_key, []))
                return items, True
            response = getattr(self.iam_client, operation)(**kwargs)
            return response.get(result_key, []), True
        except (BotoCoreError, ClientError) as exc:
            self._record_iam_error(operation, exc)
            return [], False

    # Compatibility helpers retained for callers that import AWSPEASS.
    def list_user_attached_policies(self, user_name):
        return self._paginate_iam("list_attached_user_policies", "AttachedPolicies", UserName=user_name)[0]

    def list_user_inline_policies(self, user_name):
        names, _ = self._paginate_iam("list_user_policies", "PolicyNames", UserName=user_name)
        policies = []
        for name in names:
            response, ok = self._call_iam("get_user_policy", UserName=user_name, PolicyName=name)
            if ok:
                policies.append({"PolicyName": name, "PolicyDocument": response.get("PolicyDocument", {})})
        return policies

    def list_groups_for_user(self, user_name):
        groups, ok = self._paginate_iam("list_groups_for_user", "Groups", UserName=user_name)
        if not ok:
            raise RuntimeError(f"Could not list groups for {user_name}")
        return groups

    def list_group_attached_policies(self, group_name):
        return self._paginate_iam("list_attached_group_policies", "AttachedPolicies", GroupName=group_name)[0]

    def list_group_inline_policies(self, group_name):
        names, _ = self._paginate_iam("list_group_policies", "PolicyNames", GroupName=group_name)
        policies = []
        for name in names:
            response, ok = self._call_iam("get_group_policy", GroupName=group_name, PolicyName=name)
            if ok:
                policies.append({"PolicyName": name, "PolicyDocument": response.get("PolicyDocument", {})})
        return policies

    def list_role_attached_policies(self, role_name):
        return self._paginate_iam("list_attached_role_policies", "AttachedPolicies", RoleName=role_name)[0]

    def list_role_inline_policies(self, role_name):
        names, _ = self._paginate_iam("list_role_policies", "PolicyNames", RoleName=role_name)
        policies = []
        for name in names:
            response, ok = self._call_iam("get_role_policy", RoleName=role_name, PolicyName=name)
            if ok:
                policies.append({"PolicyName": name, "PolicyDocument": response.get("PolicyDocument", {})})
        return policies

    @staticmethod
    def _policy_document(document):
        if isinstance(document, dict):
            return document
        if isinstance(document, str):
            for candidate in (document, unquote(document)):
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, dict):
                        return parsed
                except (TypeError, ValueError):
                    pass
        return {}

    @staticmethod
    def _as_list(value):
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def _get_managed_policy_document(self, policy_arn):
        response, get_policy_ok = self._call_iam("get_policy", PolicyArn=policy_arn)
        version_id = response.get("Policy", {}).get("DefaultVersionId") if get_policy_ok else None
        version_lookup_ok = get_policy_ok
        if not version_id:
            versions, version_lookup_ok = self._paginate_iam(
                "list_policy_versions", "Versions", PolicyArn=policy_arn
            )
            default = next((version for version in versions if version.get("IsDefaultVersion")), None)
            version_id = default.get("VersionId") if default else None
        if not version_id:
            return self._public_managed_policy_document(policy_arn), False
        version, version_ok = self._call_iam(
            "get_policy_version", PolicyArn=policy_arn, VersionId=version_id
        )
        document = self._policy_document(version.get("PolicyVersion", {}).get("Document"))
        if not document:
            return self._public_managed_policy_document(policy_arn), False
        return document, bool(version_lookup_ok and version_ok)

    def _load_public_managed_policy_actions(self):
        if self.public_managed_policy_actions is not None:
            return self.public_managed_policy_actions
        self.public_managed_policy_actions = {}
        try:
            response = requests.get(MANAGED_POLICIES_URL, timeout=(5, 20))
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("policies"), list):
                raise ValueError("managed-policy dataset has an unexpected shape")
            for policy in payload["policies"]:
                if not isinstance(policy, dict):
                    continue
                arn = policy.get("arn", "")
                path = arn.split(":policy/", 1)[-1] if ":policy/" in arn else ""
                actions = policy.get("effective_action_names") or []
                if path and isinstance(actions, list) and actions:
                    self.public_managed_policy_actions[path] = actions
        except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError) as exc:
            if self.debug:
                print(f"{Fore.YELLOW}[DEBUG] Public AWS-managed policy fallback failed: {exc}")
        return self.public_managed_policy_actions

    def _public_managed_policy_document(self, policy_arn):
        """Recover AWS-managed action names without requiring GetPolicyVersion."""
        if ":iam::aws:policy/" not in policy_arn:
            return {}
        path = policy_arn.split(":policy/", 1)[-1]
        actions = self._load_public_managed_policy_actions().get(path, [])
        if not actions:
            return {}
        self.policy_notes.append(
            f"Recovered actions for AWS-managed policy {path} from the public IAM dataset; "
            "resource and condition details remain unknown."
        )
        return {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
        }

    def _collect_direct_policies(self):
        """Use granular IAM APIs first because they are commonly granted for self-inspection."""
        documents = []
        complete = True
        attached_arns = set()

        if self.principal_type == "user":
            # Omitting UserName is the most permission-friendly way for an IAM
            # user to inspect itself. Retry the explicit name for unusual IAM
            # policies/proxies that require it.
            entity_response, entity_ok = self._call_iam("get_user")
            if not entity_ok:
                entity_response, entity_ok = self._call_iam(
                    "get_user", UserName=self.principal_name
                )
            complete &= entity_ok
            entity = entity_response.get("User", {})
            self.entity_arn = entity.get("Arn") or self.principal_arn
            boundary = entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if boundary:
                self.permissions_boundary_arns.add(boundary)

            attached, ok = self._paginate_iam(
                "list_attached_user_policies", "AttachedPolicies", UserName=self.principal_name
            )
            complete &= ok
            attached_arns.update(item.get("PolicyArn") for item in attached if item.get("PolicyArn"))

            inline_names, ok = self._paginate_iam(
                "list_user_policies", "PolicyNames", UserName=self.principal_name
            )
            complete &= ok
            for policy_name in inline_names:
                response, doc_ok = self._call_iam(
                    "get_user_policy", UserName=self.principal_name, PolicyName=policy_name
                )
                complete &= doc_ok
                if doc_ok:
                    document = self._policy_document(response.get("PolicyDocument"))
                    if document:
                        documents.append((f"inline user policy {policy_name}", document, False))
                    else:
                        complete = False
                        self.policy_notes.append(
                            f"Ignored an empty or malformed inline user policy {policy_name}."
                        )

            groups, groups_ok = self._paginate_iam(
                "list_groups_for_user", "Groups", UserName=self.principal_name
            )
            complete &= groups_ok
            for group in groups:
                group_name = group.get("GroupName")
                group_attached, ok = self._paginate_iam(
                    "list_attached_group_policies", "AttachedPolicies", GroupName=group_name
                )
                complete &= ok
                attached_arns.update(
                    item.get("PolicyArn") for item in group_attached if item.get("PolicyArn")
                )
                group_inline, ok = self._paginate_iam(
                    "list_group_policies", "PolicyNames", GroupName=group_name
                )
                complete &= ok
                for policy_name in group_inline:
                    response, doc_ok = self._call_iam(
                        "get_group_policy", GroupName=group_name, PolicyName=policy_name
                    )
                    complete &= doc_ok
                    if doc_ok:
                        document = self._policy_document(response.get("PolicyDocument"))
                        if document:
                            documents.append(
                                (f"inline group policy {group_name}/{policy_name}", document, False)
                            )
                        else:
                            complete = False
                            self.policy_notes.append(
                                f"Ignored an empty or malformed inline group policy "
                                f"{group_name}/{policy_name}."
                            )

        elif self.principal_type == "role":
            entity_response, entity_ok = self._call_iam("get_role", RoleName=self.principal_name)
            complete &= entity_ok
            entity = entity_response.get("Role", {})
            self.entity_arn = entity.get("Arn")
            if not self.entity_arn:
                partition = self.principal_arn.split(":", 2)[1]
                self.entity_arn = f"arn:{partition}:iam::{self.identity['Account']}:role/{self.principal_name}"
                self.policy_notes.append(
                    "The role path could not be read; simulation will try a pathless role ARN."
                )
            boundary = entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            if boundary:
                self.permissions_boundary_arns.add(boundary)

            attached, ok = self._paginate_iam(
                "list_attached_role_policies", "AttachedPolicies", RoleName=self.principal_name
            )
            complete &= ok
            attached_arns.update(item.get("PolicyArn") for item in attached if item.get("PolicyArn"))
            inline_names, ok = self._paginate_iam(
                "list_role_policies", "PolicyNames", RoleName=self.principal_name
            )
            complete &= ok
            for policy_name in inline_names:
                response, doc_ok = self._call_iam(
                    "get_role_policy", RoleName=self.principal_name, PolicyName=policy_name
                )
                complete &= doc_ok
                if doc_ok:
                    document = self._policy_document(response.get("PolicyDocument"))
                    if document:
                        documents.append((f"inline role policy {policy_name}", document, False))
                    else:
                        complete = False
                        self.policy_notes.append(
                            f"Ignored an empty or malformed inline role policy {policy_name}."
                        )
        else:
            return [], False

        for policy_arn in sorted(attached_arns):
            document, ok = self._get_managed_policy_document(policy_arn)
            complete &= ok
            if document:
                documents.append((f"managed policy {policy_arn}", document, False))
        for boundary_arn in sorted(self.permissions_boundary_arns):
            document, ok = self._get_managed_policy_document(boundary_arn)
            complete &= ok
            if document:
                documents.append((f"permissions boundary {boundary_arn}", document, True))
        return documents, complete

    def _collect_account_authorization_fallback(self):
        """Fallback to IAM's account snapshot API when granular reads were blocked."""
        pages = []
        try:
            paginator = self.iam_client.get_paginator("get_account_authorization_details")
            for page in paginator.paginate(
                Filter=["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]
            ):
                pages.append(page)
        except (BotoCoreError, ClientError) as exc:
            self._record_iam_error("get_account_authorization_details", exc)
            return [], False

        users = [item for page in pages for item in page.get("UserDetailList", [])]
        roles = [item for page in pages for item in page.get("RoleDetailList", [])]
        groups = [item for page in pages for item in page.get("GroupDetailList", [])]
        policies = [item for page in pages for item in page.get("Policies", [])]
        managed_docs = {}
        for policy in policies:
            default_id = policy.get("DefaultVersionId")
            version = next(
                (v for v in policy.get("PolicyVersionList", []) if v.get("VersionId") == default_id),
                None,
            )
            if version:
                managed_docs[policy.get("Arn")] = self._policy_document(version.get("Document"))

        if self.principal_type == "user":
            entity = next((u for u in users if u.get("UserName") == self.principal_name), None)
            inline_key = "UserPolicyList"
            related_groups = set(entity.get("GroupList", [])) if entity else set()
        elif self.principal_type == "role":
            entity = next((r for r in roles if r.get("RoleName") == self.principal_name), None)
            inline_key = "RolePolicyList"
            related_groups = set()
        else:
            return [], False
        if not entity:
            return [], False

        self.entity_arn = entity.get("Arn") or self.entity_arn
        documents = []
        complete = True
        for inline in entity.get(inline_key, []):
            document = self._policy_document(inline.get("PolicyDocument"))
            if document:
                documents.append(
                    (f"account snapshot inline policy {inline.get('PolicyName')}", document, False)
                )
            else:
                complete = False
        attached = list(entity.get("AttachedManagedPolicies", []))
        for group in groups:
            if group.get("GroupName") not in related_groups:
                continue
            for inline in group.get("GroupPolicyList", []):
                document = self._policy_document(inline.get("PolicyDocument"))
                if document:
                    documents.append(
                        (
                            f"account snapshot group policy {group.get('GroupName')}/{inline.get('PolicyName')}",
                            document,
                            False,
                        )
                    )
                else:
                    complete = False
            attached.extend(group.get("AttachedManagedPolicies", []))

        boundary_arn = entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        if boundary_arn:
            self.permissions_boundary_arns.add(boundary_arn)
        for attached_policy in attached:
            arn = attached_policy.get("PolicyArn")
            if managed_docs.get(arn):
                documents.append((f"account snapshot managed policy {arn}", managed_docs[arn], False))
            elif arn:
                complete = False
        for arn in self.permissions_boundary_arns:
            if managed_docs.get(arn):
                documents.append((f"account snapshot permissions boundary {arn}", managed_docs[arn], True))
            else:
                complete = False
        return documents, complete

    # Policy parsing and action catalog fallbacks
    def _botocore_action_catalog(self):
        permissions = {}
        for service in self.session.get_available_services():
            try:
                model = self.session._session.get_service_model(service)
            except Exception:
                continue
            prefix = model.metadata.get("signingName") or model.endpoint_prefix or service
            for operation in model.operation_names:
                normalized = self.AWSBruteForce.transform_command(f"{prefix}:{operation}")
                if ":" not in normalized:
                    continue
                normalized_prefix, action = normalized.split(":", 1)
                if normalized_prefix and action:
                    permissions.setdefault(normalized_prefix, []).append(action)
        return {service: sorted(set(actions)) for service, actions in permissions.items()}

    def download_aws_permissions(self):
        if self.action_catalog is not None:
            return self.action_catalog
        try:
            response = requests.get(POLICY_GENERATOR_URL, timeout=(5, 20))
            response.raise_for_status()
            payload = re.sub(r"^\s*app\.PolicyEditorConfig\s*=\s*", "", response.text)
            payload = payload.strip().rstrip(";")
            policies = json.loads(payload)
            if not isinstance(policies, dict) or not isinstance(policies.get("serviceMap"), dict):
                raise ValueError("AWS action catalog has an unexpected shape")
            catalog = {}
            for details in policies["serviceMap"].values():
                if not isinstance(details, dict):
                    continue
                prefix = details.get("StringPrefix")
                actions = details.get("Actions")
                if not isinstance(prefix, str) or not prefix or not isinstance(actions, list):
                    continue
                valid_actions = [action for action in actions if isinstance(action, str) and action]
                if valid_actions:
                    catalog[prefix] = valid_actions
            if not catalog:
                raise ValueError("AWS action catalog contained no valid services")
            self.action_catalog = catalog
            self.action_catalog_source = "AWS Policy Generator"
        except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError) as exc:
            if self.debug:
                print(f"{Fore.YELLOW}[DEBUG] AWS action catalog download failed: {exc}")
            self.action_catalog = self._botocore_action_catalog()
            self.action_catalog_source = "installed botocore service models (offline fallback)"
        return self.action_catalog

    def _all_actions(self):
        catalog = self.download_aws_permissions()
        return {
            f"{service}:{action}"
            for service, actions in catalog.items()
            if isinstance(service, str) and service
            for action in (actions if isinstance(actions, (list, tuple, set)) else [])
            if isinstance(action, str) and action
        }

    def _expand_not_actions(self, exclusions):
        exclusions = [value.casefold() for value in exclusions if isinstance(value, str) and value]
        if not exclusions:
            return set()
        return {
            action
            for action in self._all_actions()
            if not any(fnmatch.fnmatchcase(action.lower(), excluded) for excluded in exclusions)
        }

    def _parse_policy_documents(self, documents):
        scopes = {}
        identity_documents = [(source, doc) for source, doc, boundary in documents if not boundary]
        boundary_documents = [(source, doc) for source, doc, boundary in documents if boundary]
        unrestricted_admin = False

        def add(scope, effect, actions, source, conditional):
            entry = scopes.setdefault(scope, {"allow": set(), "deny": set(), "sources": set()})
            entry[effect].update(actions)
            entry["sources"].add(source)
            if conditional:
                self.policy_conditions.update(conditional)

        for source, document in identity_documents:
            if not isinstance(document, dict):
                self.policy_notes.append(f"Ignored malformed policy document from {source}.")
                continue
            statements = self._as_list(document.get("Statement"))
            for statement in statements:
                if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
                    continue
                action_values = self._as_list(statement.get("Action"))
                if not action_values and statement.get("NotAction") is not None:
                    action_values = sorted(self._expand_not_actions(self._as_list(statement.get("NotAction"))))
                    self.policy_notes.append(f"Expanded NotAction in {source} using the AWS action catalog.")
                action_values = {
                    action for action in action_values if isinstance(action, str) and action
                }
                resources = self._as_list(statement.get("Resource")) or ["*"]
                if statement.get("NotResource") is not None:
                    excluded = ", ".join(map(str, self._as_list(statement.get("NotResource"))))
                    resources = [f"* (except {excluded})"]
                    self.policy_notes.append(f"Preserved a NotResource scope from {source} as an exclusion label.")
                raw_conditions = statement.get("Condition")
                conditions = {} if raw_conditions is None else raw_conditions
                malformed_condition = not isinstance(conditions, dict)
                if malformed_condition:
                    self.policy_notes.append(f"Ignored a malformed Condition in {source}.")
                    self.policy_conditions.add("<malformed>")
                    conditions = {}
                for resource in resources:
                    add(
                        str(resource),
                        "allow" if statement["Effect"] == "Allow" else "deny",
                        action_values,
                        source,
                        conditions.keys(),
                    )
                if (
                    statement["Effect"] == "Allow"
                    and "*" in action_values
                    and resources == ["*"]
                    and not conditions
                    and not malformed_condition
                ):
                    unrestricted_admin = True

        boundary_allow = set()
        boundary_deny = set()
        for source, document in boundary_documents:
            if not isinstance(document, dict):
                self.policy_notes.append(f"Ignored malformed permissions boundary from {source}.")
                continue
            for statement in self._as_list(document.get("Statement")):
                if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
                    continue
                actions = {
                    action
                    for action in self._as_list(statement.get("Action"))
                    if isinstance(action, str) and action
                }
                if not actions and statement.get("NotAction") is not None:
                    actions = self._expand_not_actions(self._as_list(statement.get("NotAction")))
                raw_conditions = statement.get("Condition")
                conditions = {} if raw_conditions is None else raw_conditions
                if isinstance(conditions, dict):
                    self.policy_conditions.update(conditions.keys())
                else:
                    self.policy_conditions.add("<malformed>")
                    self.policy_notes.append(
                        f"Ignored a malformed Condition in permissions boundary {source}."
                    )
                target = boundary_allow if statement["Effect"] == "Allow" else boundary_deny
                target.update(actions)
        if boundary_documents or self.permissions_boundary_arns:
            unrestricted_admin = False
            self.policy_notes.append(
                "A permissions boundary is present. Static identity-policy allows are candidates; "
                "effective access is their intersection with the boundary."
            )
        global_denies = scopes.get("*", {}).get("deny", set())
        if global_denies:
            unrestricted_admin = False
            for scope, values in scopes.items():
                if scope != "*":
                    values["deny"].update(global_denies)
        return scopes, boundary_allow, boundary_deny, unrestricted_admin

    def extract_permissions(self, policy_document):
        scopes, _, _, _ = self._parse_policy_documents([("policy", self._policy_document(policy_document), False)])
        return {action for values in scopes.values() for action in values["allow"]}

    def extract_denied_permissions(self, policy_document):
        scopes, _, _, _ = self._parse_policy_documents([("policy", self._policy_document(policy_document), False)])
        return {action for values in scopes.values() for action in values["deny"]}

    def get_principal_permissions(self):
        self.get_caller_identity()
        direct_documents, direct_complete = self._collect_direct_policies()
        documents = list(direct_documents)

        if not direct_complete:
            print(
                f"{Fore.YELLOW}Some granular IAM reads were denied or unavailable; "
                "trying GetAccountAuthorizationDetails as an independent fallback..."
            )
            fallback_documents, fallback_ok = self._collect_account_authorization_fallback()
            known = {(source, json.dumps(doc, sort_keys=True), boundary) for source, doc, boundary in documents}
            for source, doc, boundary in fallback_documents:
                signature = (source, json.dumps(doc, sort_keys=True), boundary)
                if signature not in known:
                    documents.append((source, doc, boundary))
            complete = fallback_ok
        else:
            complete = True

        scopes, boundary_allow, boundary_deny, unrestricted_admin = self._parse_policy_documents(documents)
        allow = sorted({action for values in scopes.values() for action in values["allow"]})
        deny = sorted({action for values in scopes.values() for action in values["deny"]} | boundary_deny)
        self.iam_visibility = "complete" if complete else "partial" if documents else "none"
        return {
            "allow": allow,
            "deny": deny,
            "scopes": scopes,
            "boundary_allow": boundary_allow,
            "boundary_deny": boundary_deny,
            "unrestricted_admin": unrestricted_admin,
            "documents_found": len(documents),
            "complete": complete,
        }

    # IAM simulator (read-only) and cascading fallbacks
    def simulate_batch(self, actions, max_attempts=5):
        allowed = set()
        marker = None
        for attempt in range(max_attempts):
            try:
                while True:
                    kwargs = {"PolicySourceArn": self.entity_arn, "ActionNames": actions}
                    if marker:
                        kwargs["Marker"] = marker
                    response = self.iam_client.simulate_principal_policy(**kwargs)
                    for result in response.get("EvaluationResults", []):
                        if str(result.get("EvalDecision", "")).lower() == "allowed":
                            action = result.get("EvalActionName")
                            if isinstance(action, str) and action:
                                allowed.add(action)
                    if not response.get("IsTruncated"):
                        return allowed, True
                    marker = response.get("Marker")
                    if not marker:
                        return allowed, True
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {"Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded"}:
                    time.sleep(min(2 ** attempt, 16))
                    continue
                if self.debug:
                    print(f"{Fore.YELLOW}[DEBUG] Simulation batch failed ({code}): {exc}")
                return set(), False
            except BotoCoreError as exc:
                if self.debug:
                    print(f"{Fore.YELLOW}[DEBUG] Simulation batch failed: {exc}")
                return set(), False
        return set(), False

    def simulate_permissions(self, batch_size=100):
        batch_size = max(1, min(int(batch_size), 100))
        if self.principal_type == "role" and not self.entity_arn:
            role_response, _ = self._call_iam("get_role", RoleName=self.principal_name)
            self.entity_arn = role_response.get("Role", {}).get("Arn")
            if not self.entity_arn:
                partition = self.principal_arn.split(":", 2)[1]
                self.entity_arn = f"arn:{partition}:iam::{self.identity['Account']}:role/{self.principal_name}"
                self.policy_notes.append(
                    "Could not read the assumed role path; simulation tried a pathless IAM role ARN."
                )
        if self.principal_type not in {"user", "role"} or not self.entity_arn:
            print(
                f"{Fore.YELLOW}IAM simulation does not accept {self.principal_type} session ARNs; "
                "continuing with live read-only probes."
            )
            return [], False

        context_keys, context_ok = self._paginate_iam(
            "get_context_keys_for_principal_policy",
            "ContextKeyNames",
            PolicySourceArn=self.entity_arn,
        )
        if context_keys:
            self.policy_notes.append(
                "Simulator context values were unavailable for: " + ", ".join(sorted(context_keys))
            )
        elif not context_ok:
            self.policy_notes.append(
                "Could not enumerate simulator context keys; conditional results may be incomplete."
            )

        all_actions = sorted(self._all_actions())
        if not all_actions:
            print(f"{Fore.YELLOW}No action catalog was available for IAM simulation.")
            return [], False
        batches = [all_actions[index:index + batch_size] for index in range(0, len(all_actions), batch_size)]
        print(
            f"{Fore.GREEN}Simulating {len(all_actions)} actions in {len(batches)} read-only batches "
            f"(catalog: {self.action_catalog_source})..."
        )
        allowed = set()
        successful_batches = 0
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(self.simulate_batch, batch) for batch in batches]
            for future in tqdm(as_completed(futures), total=len(futures), desc="Simulating permissions"):
                try:
                    batch_allowed, ok = future.result()
                except Exception as exc:
                    if self.debug:
                        print(f"{Fore.YELLOW}[DEBUG] Unexpected simulator worker failure: {exc}")
                    self.policy_notes.append("An IAM simulator worker failed unexpectedly.")
                    continue
                allowed.update(batch_allowed)
                successful_batches += int(ok)
        if successful_batches == 0:
            print(f"{Fore.YELLOW}IAM simulation was unavailable; moving to the next fallback.")
            return [], False
        if successful_batches != len(batches):
            self.policy_notes.append(
                f"IAM simulation was partial: {successful_batches}/{len(batches)} batches completed."
            )
        complete = successful_batches == len(batches)
        if complete and allowed == set(all_actions):
            self.simulation_is_admin = True
            self.policy_notes.append(
                "IAM simulation allowed every action in the current AWS catalog; compacted to '*'."
            )
            return ["*"], True
        return sorted(allowed), complete

    def _account_resource(self, permissions, deny_perms=None, is_admin=False, method=None):
        account_id = self.identity.get("Account")
        partition = self.principal_arn.split(":", 2)[1]
        if method == "managed-policy inference":
            resource_id = f"inferred://aws/{account_id}/managed-policy-candidate"
            name = f"Unconfirmed managed-policy inference for {account_id}"
            resource_type = "inferred permissions (not confirmed)"
        else:
            resource_id = f"arn:{partition}:iam::{account_id}:root"
            name = f"AWS account {account_id}"
            resource_type = "account"
        return CloudResource(
            resource_id=resource_id,
            name=name,
            resource_type=resource_type,
            permissions=sorted(set(permissions)),
            deny_perms=sorted(set(deny_perms or [])),
            is_admin=is_admin,
            evidence=method,
        )

    def _scope_resource(self, scope, values):
        if scope == "*":
            return self._account_resource(values["allow"], values["deny"], method="IAM policies")
        name = scope.rsplit("/", 1)[-1] if "/" in scope else scope
        return CloudResource(
            resource_id=scope,
            name=name,
            resource_type="policy scope",
            permissions=sorted(values["allow"]),
            deny_perms=sorted(values["deny"]),
            evidence="IAM policies",
        )

    def _guess_managed_policy_permissions(self, bf_permissions, resources):
        if not bf_permissions or self.skip_managed_policies_guess:
            return
        if self.no_ask:
            answer = "y"
        else:
            answer = input(
                f"{Fore.YELLOW}Try public managed-policy inference from the read permissions found? (Y/n): {Fore.RESET}"
            ).strip().lower()
        if answer == "n":
            return
        try:
            guessed = AWSManagedPoliciesGuesser(set(bf_permissions)).guess_permissions()
        except (RuntimeError, requests.RequestException, ValueError) as exc:
            print(f"{Fore.YELLOW}Managed-policy inference was unavailable: {exc}")
            return
        if not guessed:
            print(f"{Fore.YELLOW}No matching managed-policy combinations were found.")
            return
        combinations = list(guessed.values())
        print(f"{Fore.BLUE}Managed-policy inference produced {len(combinations)} possible combinations.")
        for index, value in enumerate(combinations, 1):
            print(
                f"{Fore.YELLOW}[{index}] {len(value['permissions'])} permissions via: "
                f"{Fore.CYAN}{', '.join(value['policies'])}"
            )
        if self.no_ask:
            selection = 1
        else:
            while True:
                raw = input(
                    f"{Fore.YELLOW}Add which inferred combination (1-{len(combinations)}), or 0 for none? [1]: {Fore.RESET}"
                ).strip() or "1"
                try:
                    selection = int(raw)
                except ValueError:
                    print(f"{Fore.RED}Enter a number between 0 and {len(combinations)}.")
                    continue
                if 0 <= selection <= len(combinations):
                    break
                print(f"{Fore.RED}Enter a number between 0 and {len(combinations)}.")
        if selection:
            resources.append(
                self._account_resource(
                    combinations[selection - 1]["permissions"], method="managed-policy inference"
                )
            )

    def get_resources_and_permissions(self):
        self.get_caller_identity()
        resources = []
        policy_result = {
            "allow": [],
            "deny": [],
            "scopes": {},
            "unrestricted_admin": False,
            "complete": False,
        }

        if self.principal_type == "root":
            print(
                f"{Fore.RED}{Back.YELLOW} ROOT CREDENTIALS DETECTED - identity permissions are account-wide; "
                f"Organizations policies may still restrict them. {Style.RESET_ALL}"
            )
            resources.append(self._account_resource(["*"], is_admin=True, method="root principal"))
            if self.bruteforce_always and not self.skip_bruteforce:
                print(
                    f"{Fore.CYAN}[3/3] Validating root read access with explicitly requested "
                    "live read-only probes (Organizations policies may restrict the root)."
                )
                live_permissions = sorted(set(self.AWSBruteForce.brute_force_permissions()))
                if live_permissions:
                    resources.append(
                        self._account_resource(live_permissions, method="live read-only probes")
                    )
            self.iam_visibility = "not applicable (root principal)"
            self.principal_info.update({
                "iam_visibility": self.iam_visibility,
                "permissions_boundaries": [],
                "policy_condition_operators": [],
                "assumed_role_session": False,
            })
            return resources

        if not self.skip_iam_policies:
            print(f"{Fore.CYAN}[1/3] Reading identity policies (granular APIs, then account-snapshot fallback)...")
            policy_result = self.get_principal_permissions()
            for scope, values in policy_result["scopes"].items():
                resources.append(self._scope_resource(scope, values))
            print(
                f"{Fore.BLUE}IAM policy visibility: {self.iam_visibility}; "
                f"{policy_result.get('documents_found', 0)} policy document(s), "
                f"{len(policy_result['allow'])} allowed action pattern(s), "
                f"{len(policy_result['deny'])} explicit deny pattern(s)."
            )
        else:
            print(f"{Fore.YELLOW}[1/3] IAM policy reads skipped by --skip-iam-policies.")

        is_admin = self._is_admin_aws(
            policy_result["allow"],
            policy_result["deny"],
            unrestricted=policy_result.get("unrestricted_admin", False),
        )
        if is_admin:
            print(
                f"{Fore.RED}{Back.YELLOW} UNCONDITIONAL IDENTITY-POLICY ADMIN CANDIDATE DETECTED. "
                f"Validating policy layers with the next available read-only method. {Style.RESET_ALL}"
            )

        needs_fallback = (
            not policy_result["complete"]
            or not policy_result["allow"]
            or bool(policy_result["deny"])
            or bool(self.permissions_boundary_arns)
            or bool(self.policy_conditions)
            or self.is_session_principal
            or is_admin
        )
        simulation_permissions = []
        simulation_complete = False
        if self.skip_simulation:
            print(f"{Fore.YELLOW}[2/3] IAM simulation skipped by --skip-simulation.")
        elif needs_fallback:
            print(f"{Fore.CYAN}[2/3] Trying IAM simulation (read-only; it does not execute actions)...")
            simulation_permissions, simulation_complete = self.simulate_permissions()
            if simulation_permissions:
                resources.append(
                    self._account_resource(
                        simulation_permissions,
                        is_admin=self.simulation_is_admin and not self.is_session_principal,
                        method="IAM policy simulator",
                    )
                )
        else:
            print(f"{Fore.GREEN}[2/3] Full IAM policy documents were read; simulation is not needed.")

        run_bruteforce = self.bruteforce_always or (
            needs_fallback
            and (not simulation_complete or not simulation_permissions or self.is_session_principal)
        )
        bf_permissions = []
        if self.skip_bruteforce:
            print(f"{Fore.YELLOW}[3/3] Live read-only probes skipped by --skip-bruteforce.")
        elif run_bruteforce:
            print(
                f"{Fore.CYAN}[3/3] Trying live read-only List/Get/Describe probes. "
                "No create, update, delete, invoke, run, start, send, or execute operations are used."
            )
            bf_permissions = sorted(set(self.AWSBruteForce.brute_force_permissions()))
            if bf_permissions:
                resources.append(self._account_resource(bf_permissions, method="live read-only probes"))
                self._guess_managed_policy_permissions(bf_permissions, resources)
        else:
            print(f"{Fore.GREEN}[3/3] Earlier methods were complete; live probes are not needed.")

        if self.permissions_boundary_arns:
            print(f"{Fore.YELLOW}Permissions boundary detected: {', '.join(sorted(self.permissions_boundary_arns))}")
        if self.policy_conditions:
            print(f"{Fore.YELLOW}Conditional policies detected ({', '.join(sorted(self.policy_conditions))}).")
        for note in dict.fromkeys(self.policy_notes):
            print(f"{Fore.YELLOW}Note: {note}")
        if self.iam_errors:
            denied = sum(1 for error in self.iam_errors if error["code"] in AUTHORIZATION_ERRORS)
            print(
                f"{Fore.BLUE}IAM fallback summary: {len(self.iam_errors)} read call(s) failed "
                f"({denied} authorization failure(s)); other methods continued where possible."
            )
        self.principal_info.update({
            "iam_visibility": self.iam_visibility,
            "permissions_boundaries": sorted(self.permissions_boundary_arns),
            "policy_condition_operators": sorted(self.policy_conditions),
            "assumed_role_session": self.is_session_principal,
        })
        return resources

    @staticmethod
    def _is_admin_aws(permissions, deny_permissions=None, unrestricted=None):
        """Only an unconditional account-wide wildcard is AWS administrator access."""
        normalized = {str(permission).strip().lower() for permission in permissions}
        denied = {str(permission).strip().lower() for permission in (deny_permissions or [])}
        wildcard = bool(normalized & {"*", "*:*"})
        if unrestricted is not None:
            wildcard = wildcard and unrestricted
        return wildcard and not denied


# Keep both spellings import-compatible. The CLI/file name remains AWSPEAS.py.
AWSPEAS = AWSPEASS


def build_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Enumerate the current AWS principal's permissions using read-only methods.\n"
            "Fallback order: IAM policy reads -> IAM simulation -> live read-only CLI probes.\n"
            "No AWS create/update/delete/invoke/run/start/send/execute operation is performed."
        ),
    )
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--profile", help="AWS profile (otherwise use the normal AWS credential chain)")
    auth_group.add_argument("--access-key-id", help="AWS access key ID (prefer environment variables when possible)")
    parser.add_argument("--secret-access-key", help="AWS secret access key; required with --access-key-id")
    parser.add_argument("--session-token", help="AWS session token for temporary explicit credentials")
    parser.add_argument("--region", help="Region for regional probes (session/env region, then us-east-1)")
    parser.add_argument("--out-json-path", help="Write JSON analysis results to this local path")
    parser.add_argument("--threads", default=10, type=int, help="Concurrent read-only calls (default: 10)")
    parser.add_argument("--debug", action="store_true", help="Show failed calls and unhandled probe responses")
    parser.add_argument(
        "--aws-services",
        help="Comma-separated services for live probes, for example: s3,ec2,lambda,iam",
    )
    parser.add_argument("--skip-iam-policies", action="store_true", help="Skip identity-policy enumeration")
    parser.add_argument("--skip-simulation", action="store_true", help="Skip IAM SimulatePrincipalPolicy")
    parser.add_argument("--skip-bruteforce", action="store_true", help="Skip live read-only API probes")
    parser.add_argument(
        "--bruteforce-always",
        action="store_true",
        help="Run live read-only probes even when policy enumeration is complete",
    )
    parser.add_argument(
        "--skip-managed-policies-guess",
        action="store_true",
        help="Skip public-dataset managed-policy inference after live probes",
    )
    parser.add_argument(
        "--no-ask",
        action="store_true",
        help="Do not prompt; use defaults (but stop safely on possible canary credentials)",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.access_key_id and not args.secret_access_key:
        parser.error("--secret-access-key is required with --access-key-id")
    if not args.access_key_id and (args.secret_access_key or args.session_token):
        parser.error("--secret-access-key/--session-token require --access-key-id")

    aws_services = [service.strip() for service in (args.aws_services or "").split(",") if service.strip()]
    try:
        aws_peass = AWSPEASS(
            args.profile,
            very_sensitive_combinations,
            sensitive_combinations,
            num_threads=args.threads,
            debug=args.debug,
            region=args.region,
            aws_services=aws_services,
            skip_iam_policies=args.skip_iam_policies,
            skip_simulation=args.skip_simulation,
            skip_bruteforce=args.skip_bruteforce,
            skip_managed_policies_guess=args.skip_managed_policies_guess,
            out_path=args.out_json_path,
            access_key_id=args.access_key_id,
            secret_access_key=args.secret_access_key,
            session_token=args.session_token,
            no_ask=args.no_ask,
            bruteforce_always=args.bruteforce_always,
        )
        aws_peass.run_analysis()
    except (NoCredentialsError, RuntimeError, BotoCoreError, ClientError) as exc:
        print(f"{Fore.RED}AWSPEAS could not start: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
