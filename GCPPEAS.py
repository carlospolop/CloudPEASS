#!/usr/bin/env python3
"""Read-only GCP permission and attack-surface enumerator."""

from __future__ import annotations

import argparse
import os
import re
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import google.auth
import google.oauth2.credentials
import google.oauth2.service_account
import requests
from colorama import Fore, init
from google.auth.transport.requests import Request
from tqdm import tqdm

from src.CloudPEASS.cloudpeass import CloudPEASS, CloudResource
from src.gcp.client import GCPApiError, GCPReadOnlyClient
from src.gcp.definitions import (
    NOT_COMPUTE_PERMS,
    NOT_FOLDER_PERMS,
    NOT_FUNCTIONS_PERMS,
    NOT_ORGANIZATION_PERMS,
    NOT_PROJECT_PERMS,
    NOT_SA_PERMS,
    NOT_STORAGE_PERMS,
)
from src.sensitive_permissions.gcp import sensitive_combinations, very_sensitive_combinations


init(autoreset=True)

IAM_API = "https://iam.googleapis.com/v1"
CRM_API = "https://cloudresourcemanager.googleapis.com/v3"
CATALOG_URL = (
    "https://raw.githubusercontent.com/iann0036/iam-dataset/"
    "refs/heads/main/gcp/permissions.json"
)
TEST_CHUNK_SIZE = 100

TYPE_PREFIXES = {
    "vm": ("compute.instances.",),
    "function": ("cloudfunctions.functions.",),
    "storage": ("storage.buckets.", "storage.objects."),
    "service_account": ("iam.serviceAccounts.", "iam.serviceAccountKeys."),
    "secret": ("secretmanager.secrets.", "secretmanager.versions."),
    "run_service": ("run.services.", "run.routes.", "run.revisions."),
    "run_job": ("run.jobs.", "run.executions.", "run.tasks."),
    "artifact_repository": ("artifactregistry.repositories.",),
    "pubsub_topic": ("pubsub.topics.",),
    "pubsub_subscription": ("pubsub.subscriptions.",),
    "bigquery_dataset": ("bigquery.datasets.", "bigquery.tables."),
    "workflow": ("workflows.workflows.", "workflowexecutions.executions."),
    "kms_keyring": ("cloudkms.keyRings.",),
    "kms_key": ("cloudkms.cryptoKeys.", "cloudkms.cryptoKeyVersions."),
}

ASSET_TYPE_HINTS = {
    "compute.googleapis.com/Instance": "vm",
    "cloudfunctions.googleapis.com/CloudFunction": "function",
    "cloudfunctions.googleapis.com/Function": "function",
    "storage.googleapis.com/Bucket": "storage",
    "iam.googleapis.com/ServiceAccount": "service_account",
    "secretmanager.googleapis.com/Secret": "secret",
    "run.googleapis.com/Service": "run_service",
    "run.googleapis.com/Job": "run_job",
    "artifactregistry.googleapis.com/Repository": "artifact_repository",
    "pubsub.googleapis.com/Topic": "pubsub_topic",
    "pubsub.googleapis.com/Subscription": "pubsub_subscription",
    "bigquery.googleapis.com/Dataset": "bigquery_dataset",
    "workflows.googleapis.com/Workflow": "workflow",
    "cloudkms.googleapis.com/KeyRing": "kms_keyring",
    "cloudkms.googleapis.com/CryptoKey": "kms_key",
}


def _csv(value: Optional[str]) -> List[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _chunks(values: Sequence[str], size: int = TEST_CHUNK_SIZE) -> Iterable[List[str]]:
    for offset in range(0, len(values), size):
        yield list(values[offset : offset + size])


class GCPPEASS(CloudPEASS):
    """Enumerate effective GCP permissions without changing cloud state."""

    def __init__(
        self,
        credentials,
        extra_token,
        projects,
        folders,
        orgs,
        sas,
        very_sensitive_combos,
        sensitive_combos,
        num_threads,
        out_path,
        billing_project,
        proxy,
        print_invalid_perms,
        dont_get_iam_policies,
        skip_bruteforce=False,
        no_ask=False,
        resources=None,
        skip_asset_inventory=False,
        timeout=20,
        retries=3,
        insecure=False,
        debug=False,
        only_specified=False,
    ):
        self.credentials = credentials
        self.extra_token = extra_token
        self.projects = _csv(projects)
        self.folders = _csv(folders)
        self.orgs = _csv(orgs)
        self.sas = _csv(sas)
        self.explicit_resources = list(resources or [])
        self.billing_project = (billing_project or "").strip()
        self.email = ""
        self.is_sa = False
        self.groups: List[str] = []
        self.print_invalid_perms = print_invalid_perms
        self.dont_get_iam_policies = dont_get_iam_policies
        self.skip_bruteforce = skip_bruteforce
        self.no_ask = no_ask  # Compatibility only; enumeration is non-interactive.
        self.skip_asset_inventory = skip_asset_inventory
        self.debug = debug
        self.max_permissions_per_category = 50
        self.only_specified = only_specified
        self.client = GCPReadOnlyClient(
            credentials,
            billing_project=self.billing_project,
            proxy=proxy,
            timeout=timeout,
            retries=retries,
            verify_tls=not insecure,
        )
        self._role_permissions: Dict[str, List[str]] = {}
        self._testable_cache: Dict[Tuple[str, str], List[str]] = {}
        self._cache_lock = threading.Lock()
        self._invalid_permissions: Dict[str, Set[str]] = defaultdict(set)
        self._failures: Dict[str, List[Tuple[str, GCPApiError]]] = defaultdict(list)
        self._conditional_bindings_skipped = 0
        self._asset_inventory_success: Set[str] = set()
        self.all_gcp_perms = self._load_permission_catalog()

        super().__init__(very_sensitive_combos, sensitive_combos, "GCP", num_threads, out_path)

    # Permission catalog -------------------------------------------------

    def _load_permission_catalog(self) -> List[str]:
        """Build a current catalog from official roles, with two safe fallbacks."""
        print(f"{Fore.BLUE}Loading the GCP permission catalog...")
        permissions: Set[str] = set()
        try:
            for page in self.client.iter_pages(
                "GET", f"{IAM_API}/roles", params={"view": "FULL", "pageSize": 1000}
            ):
                for role in page.get("roles", []):
                    name = role.get("name")
                    included = sorted(set(role.get("includedPermissions") or []))
                    if name and included:
                        self._role_permissions[name] = included
                        permissions.update(included)
            if permissions:
                print(
                    f"{Fore.GREEN}Loaded {len(permissions)} permissions from "
                    f"{len(self._role_permissions)} official predefined roles."
                )
                return sorted(permissions)
        except GCPApiError as exc:
            print(f"{Fore.YELLOW}Official IAM catalog unavailable ({exc}); trying the public fallback.")

        try:
            proxies = (
                {"http": self.client.proxy, "https": self.client.proxy}
                if self.client.proxy
                else None
            )
            response = requests.get(
                CATALOG_URL,
                timeout=self.client.timeout,
                proxies=proxies,
                verify=self.client.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("unexpected catalog format")
            for permission, roles in payload.items():
                if not isinstance(permission, str):
                    continue
                permissions.add(permission)
                for role in roles if isinstance(roles, list) else []:
                    if isinstance(role, dict) and role.get("id"):
                        self._role_permissions.setdefault(role["id"], []).append(permission)
            if permissions:
                for role in self._role_permissions:
                    self._role_permissions[role] = sorted(set(self._role_permissions[role]))
                print(f"{Fore.GREEN}Loaded {len(permissions)} permissions from the public fallback catalog.")
                return sorted(permissions)
        except (requests.RequestException, ValueError, TypeError) as exc:
            print(f"{Fore.YELLOW}Public catalog unavailable ({type(exc).__name__}); using the built-in core set.")

        for values in (
            NOT_COMPUTE_PERMS,
            NOT_FUNCTIONS_PERMS,
            NOT_STORAGE_PERMS,
            NOT_SA_PERMS,
            NOT_PROJECT_PERMS,
            NOT_FOLDER_PERMS,
            NOT_ORGANIZATION_PERMS,
        ):
            permissions.update(values)
        for combo in list(very_sensitive_combinations) + list(sensitive_combinations):
            permissions.update(combo)
        print(f"{Fore.YELLOW}Using {len(permissions)} built-in core permissions; results may be incomplete.")
        return sorted(permissions)

    def _query_testable_permissions(self, target: dict) -> List[str]:
        cache_key = (target["type"], target.get("api_version", ""))
        with self._cache_lock:
            cached = self._testable_cache.get(cache_key)
        if cached is not None:
            return cached

        found: Set[str] = set()
        try:
            for page in self.client.iter_pages(
                "POST",
                f"{IAM_API}/permissions:queryTestablePermissions",
                json={"fullResourceName": target["full_name"], "pageSize": 1000},
                token_in_body=True,
            ):
                for permission in page.get("permissions", []):
                    name = permission.get("name") if isinstance(permission, dict) else None
                    if name:
                        found.add(name)
        except GCPApiError as exc:
            # Some services implement testIamPermissions but do not support
            # queryTestablePermissions for their resource names. A 400 is an
            # expected signal to use the service-prefix catalog below.
            if exc.status != 400:
                self._record_failure(
                    f"testable permission catalog ({target['type']})",
                    target.get("project", "global"),
                    exc,
                )

        result = sorted(found) if found else self.get_relevant_permissions(target["type"])
        with self._cache_lock:
            self._testable_cache.setdefault(cache_key, result)
            return self._testable_cache[cache_key]

    def get_relevant_permissions(self, res_type=None):
        res_type = (res_type or "").lower()
        if res_type in {"project", "folder", "organization"}:
            exclusions = {
                "project": set(NOT_PROJECT_PERMS),
                "folder": set(NOT_FOLDER_PERMS),
                "organization": set(NOT_ORGANIZATION_PERMS),
            }[res_type]
            return [permission for permission in self.all_gcp_perms if permission not in exclusions]
        prefixes = TYPE_PREFIXES.get(res_type)
        if prefixes:
            return [permission for permission in self.all_gcp_perms if permission.startswith(prefixes)]
        return list(self.all_gcp_perms)

    # Resource names and permissionless/local discovery -----------------

    @staticmethod
    def _project_from_path(path: str) -> str:
        match = re.search(r"(?:^|/)projects/([^/]+)", path)
        return match.group(1) if match else ""

    def _target(
        self,
        resource_id: str,
        resource_type: str,
        *,
        project: str = "",
        full_name: str = "",
        api_version: str = "",
        source: str = "discovered",
    ) -> dict:
        return {
            "id": resource_id.strip("/"),
            "type": resource_type,
            "project": project or self._project_from_path(resource_id),
            "full_name": full_name,
            "api_version": api_version,
            "source": source,
        }

    def normalize_resource(
        self,
        value: str,
        *,
        project_hint: str = "",
        asset_type: str = "",
        source: str = "explicit",
    ) -> Optional[dict]:
        """Normalize CLI, API, Cloud Asset, and metadata resource names."""
        raw = (value or "").strip()
        if not raw:
            return None

        if raw.startswith("project:"):
            raw = f"projects/{raw.split(':', 1)[1]}"
        elif raw.startswith("folder:"):
            raw = f"folders/{raw.split(':', 1)[1]}"
        elif raw.startswith("organization:"):
            raw = f"organizations/{raw.split(':', 1)[1]}"
        elif raw.startswith("bucket:"):
            raw = f"buckets/{raw.split(':', 1)[1]}"
        elif raw.startswith("service-account:"):
            email = raw.split(":", 1)[1]
            sa_project = email.split("@", 1)[1].split(".", 1)[0] if "@" in email else project_hint
            raw = f"projects/{sa_project}/serviceAccounts/{email}"
        elif raw.startswith("function-v2:"):
            raw = raw.split(":", 1)[1]
            asset_type = "cloudfunctions.googleapis.com/Function"
        elif raw.startswith("gs://"):
            raw = f"buckets/{raw[5:].split('/', 1)[0]}"

        host = ""
        full_name = ""
        path = raw.strip("/")
        if raw.startswith("//"):
            full_name = raw.rstrip("/")
            host_and_path = raw[2:].split("/", 1)
            host = host_and_path[0].lower()
            path = host_and_path[1].strip("/") if len(host_and_path) == 2 else ""

        hinted_type = ASSET_TYPE_HINTS.get(asset_type, "")
        project = project_hint or self._project_from_path(path)
        resource_type = ""
        api_version = ""

        if re.fullmatch(r"projects/[^/]+", path):
            resource_type, host = "project", host or "cloudresourcemanager.googleapis.com"
        elif re.fullmatch(r"folders/\d+", path):
            resource_type, host = "folder", host or "cloudresourcemanager.googleapis.com"
        elif re.fullmatch(r"organizations/\d+", path):
            resource_type, host = "organization", host or "cloudresourcemanager.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/zones/[^/]+/instances/[^/]+", path):
            resource_type, host = "vm", host or "compute.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/locations/[^/]+/functions/[^/]+", path):
            resource_type, host = "function", host or "cloudfunctions.googleapis.com"
            if asset_type:
                api_version = "v2" if asset_type.endswith("/Function") else "v1"
        elif path.startswith("buckets/") or host == "storage.googleapis.com" or "/storage/" in path:
            resource_type, host = "storage", "storage.googleapis.com"
            if "/storage/" in path:
                bucket = path.rsplit("/storage/", 1)[1]
            elif "/buckets/" in path:
                bucket = path.rsplit("/buckets/", 1)[1]
            else:
                bucket = path.split("/", 1)[-1]
            path = f"projects/{project or '_'}/buckets/{bucket}"
        elif re.fullmatch(r"projects/[^/]+/serviceAccounts/[^/]+", path):
            resource_type, host = "service_account", host or "iam.googleapis.com"
        elif re.fullmatch(
            r"projects/[^/]+/(?:locations/[^/]+/)?secrets/[^/]+", path
        ):
            resource_type, host = "secret", host or "secretmanager.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/locations/[^/]+/services/[^/]+", path):
            resource_type, host = "run_service", "run.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/locations/[^/]+/jobs/[^/]+", path):
            resource_type, host = "run_job", "run.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/locations/[^/]+/repositories/[^/]+", path):
            resource_type, host = "artifact_repository", host or "artifactregistry.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/topics/[^/]+", path):
            resource_type, host = "pubsub_topic", host or "pubsub.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/subscriptions/[^/]+", path):
            resource_type, host = "pubsub_subscription", host or "pubsub.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/datasets/[^/]+", path):
            resource_type, host = "bigquery_dataset", host or "bigquery.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/locations/[^/]+/workflows/[^/]+", path):
            resource_type, host = "workflow", host or "workflows.googleapis.com"
        elif re.fullmatch(
            r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+", path
        ):
            resource_type, host = "kms_key", host or "cloudkms.googleapis.com"
        elif re.fullmatch(r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+", path):
            resource_type, host = "kms_keyring", host or "cloudkms.googleapis.com"

        # A recognized Cloud Asset type must also have the expected name shape.
        if hinted_type and resource_type != hinted_type:
            resource_type = ""

        if not resource_type:
            return None
        full_name = full_name or f"//{host}/{path}"
        return self._target(
            path,
            resource_type,
            project=project,
            full_name=full_name,
            api_version=api_version,
            source=source,
        )

    @staticmethod
    def _metadata_get(path: str, timeout: float = 0.4) -> str:
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(
                f"http://169.254.169.254/computeMetadata/v1/{path}",
                headers={"Metadata-Flavor": "Google"},
                timeout=timeout,
            )
            if response.status_code == 200 and response.headers.get("Metadata-Flavor") == "Google":
                return response.text.strip()
        except requests.RequestException:
            pass
        return ""

    def discover_metadata_targets(self) -> List[dict]:
        """Use GCE metadata when available; this requires no IAM permission."""
        project = self._metadata_get("project/project-id")
        if not project:
            return []
        targets = [self.normalize_resource(f"projects/{project}", source="metadata")]
        zone = self._metadata_get("instance/zone").rsplit("/", 1)[-1]
        instance = self._metadata_get("instance/name")
        if zone and instance:
            targets.append(
                self.normalize_resource(
                    f"projects/{project}/zones/{zone}/instances/{instance}", source="metadata"
                )
            )
        sa_email = self._metadata_get("instance/service-accounts/default/email")
        if sa_email:
            targets.append(
                self.normalize_resource(
                    f"projects/{project}/serviceAccounts/{sa_email}", source="metadata"
                )
            )
        return [target for target in targets if target]

    # Container and service discovery -----------------------------------

    def _record_failure(self, operation: str, project: str, error: GCPApiError) -> None:
        with self._cache_lock:
            self._failures[project or "global"].append((operation, error))
        if self.debug:
            print(f"{Fore.YELLOW}{operation} failed for {project or 'global'}: {error}")

    def _paged_items(self, url: str, key: str, *, params=None) -> List[dict]:
        items: List[dict] = []
        for page in self.client.iter_pages("GET", url, params=params):
            values = page.get(key, [])
            if isinstance(values, list):
                items.extend(value for value in values if isinstance(value, dict))
        return items

    def list_projects(self) -> List[str]:
        try:
            items = self._paged_items(
                f"{CRM_API}/projects:search", "projects", params={"pageSize": 1000}
            )
            return sorted({item["projectId"] for item in items if item.get("projectId")})
        except GCPApiError as exc:
            self._record_failure("project search", "global", exc)
            return []

    def list_folders(self) -> List[str]:
        try:
            items = self._paged_items(
                f"{CRM_API}/folders:search", "folders", params={"pageSize": 1000}
            )
            return sorted({item["name"].split("/")[-1] for item in items if item.get("name")})
        except GCPApiError as exc:
            self._record_failure("folder search", "global", exc)
            return []

    def list_organizations(self) -> List[str]:
        try:
            items = self._paged_items(
                f"{CRM_API}/organizations:search",
                "organizations",
                params={"pageSize": 1000},
            )
            return sorted({item["name"].split("/")[-1] for item in items if item.get("name")})
        except GCPApiError as exc:
            self._record_failure("organization search", "global", exc)
            return []

    def _discover_assets(self, project: str) -> List[dict]:
        if self.skip_asset_inventory:
            return []
        targets: List[dict] = []
        try:
            for page in self.client.iter_pages(
                "GET",
                f"https://cloudasset.googleapis.com/v1/projects/{project}:searchAllResources",
                params={
                    "pageSize": 500,
                    "readMask": "name,assetType,project,location,displayName",
                },
            ):
                for item in page.get("results", []):
                    target = self.normalize_resource(
                        item.get("name", ""),
                        project_hint=project,
                        asset_type=item.get("assetType", ""),
                        source="Cloud Asset Inventory",
                    )
                    if target:
                        targets.append(target)
            with self._cache_lock:
                self._asset_inventory_success.add(project)
        except GCPApiError as exc:
            self._record_failure("Cloud Asset Inventory", project, exc)
        return targets

    def _discover_compute(self, project: str) -> List[dict]:
        targets = []
        for page in self.client.iter_pages(
            "GET",
            f"https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances",
            params={"maxResults": 500},
        ):
            for scoped in page.get("items", {}).values():
                if not isinstance(scoped, dict):
                    continue
                for instance in scoped.get("instances", []):
                    zone = (instance.get("zone") or "").rsplit("/", 1)[-1]
                    name = instance.get("name")
                    if zone and name:
                        targets.append(
                            self.normalize_resource(
                                f"projects/{project}/zones/{zone}/instances/{name}",
                                source="Compute list",
                            )
                        )
        return targets

    def _discover_functions(self, project: str, version: str) -> List[dict]:
        targets = []
        for item in self._paged_items(
            f"https://cloudfunctions.googleapis.com/{version}/projects/{project}/locations/-/functions",
            "functions",
            params={"pageSize": 1000},
        ):
            target = self.normalize_resource(item.get("name", ""), source=f"Functions {version} list")
            if target:
                target["api_version"] = version
                targets.append(target)
        return targets

    def _discover_storage(self, project: str) -> List[dict]:
        return [
            self.normalize_resource(
                f"//storage.googleapis.com/projects/_/buckets/{item['name']}",
                project_hint=project,
                source="Storage list",
            )
            for item in self._paged_items(
                "https://storage.googleapis.com/storage/v1/b",
                "items",
                params={
                    "project": project,
                    "maxResults": 1000,
                    "fields": "items(name),nextPageToken",
                },
            )
            if item.get("name")
        ]

    def _discover_service_accounts(self, project: str) -> List[dict]:
        return [
            self.normalize_resource(item.get("name", ""), source="Service account list")
            for item in self._paged_items(
                f"{IAM_API}/projects/{project}/serviceAccounts",
                "accounts",
                params={"pageSize": 100},
            )
            if item.get("name")
        ]

    def _discover_secrets(self, project: str) -> List[dict]:
        return [
            self.normalize_resource(item.get("name", ""), source="Secret Manager list")
            for item in self._paged_items(
                f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets",
                "secrets",
                params={"pageSize": 1000},
            )
            if item.get("name")
        ]

    def _discover_run(self, project: str, collection: str) -> List[dict]:
        targets = []
        if collection == "services":
            # The v1 Knative-compatible endpoint lists every region. Cloud Run
            # v2 explicitly rejects locations/- for services. This Kubernetes-
            # style API paginates with metadata.continue instead of the usual
            # nextPageToken.
            url = (
                "https://run.googleapis.com/apis/serving.knative.dev/v1/"
                f"namespaces/{project}/services"
            )
            params = {"limit": 1000}
            items = []
            while True:
                page = self.client.request("GET", url, params=params)
                items.extend(page.get("items") or [])
                token = (page.get("metadata") or {}).get("continue")
                if not token:
                    break
                params["continue"] = token
            for item in items:
                metadata = item.get("metadata") or {}
                labels = metadata.get("labels") or {}
                name = metadata.get("name")
                location = labels.get("cloud.googleapis.com/location")
                if name and location:
                    targets.append(
                        self.normalize_resource(
                            f"//run.googleapis.com/projects/{project}/locations/{location}/services/{name}",
                            source="Cloud Run services list",
                        )
                    )
            return targets

        # Jobs have no cross-region list endpoint. Listing public locations is
        # permissionless; stop immediately if the first region proves that the
        # principal lacks run.jobs.list at project scope.
        locations = self._paged_items(
            f"https://run.googleapis.com/v1/projects/{project}/locations",
            "locations",
            params={"pageSize": 1000},
        )
        for location_info in locations:
            location = (location_info.get("name") or "").rsplit("/", 1)[-1]
            if not location:
                continue
            try:
                items = self._paged_items(
                    f"https://run.googleapis.com/v2/projects/{project}/locations/{location}/jobs",
                    "jobs",
                    params={"pageSize": 1000},
                )
            except GCPApiError as exc:
                if exc.status in {401, 403}:
                    raise
                continue
            for item in items:
                if item.get("name"):
                    targets.append(
                        self.normalize_resource(item["name"], source="Cloud Run jobs list")
                    )
        return targets

    def _discover_artifacts(self, project: str) -> List[dict]:
        targets = []
        locations = self._paged_items(
            f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations",
            "locations",
            params={"pageSize": 1000},
        )
        for location_info in locations:
            location = (location_info.get("name") or "").rsplit("/", 1)[-1]
            if not location:
                continue
            items = self._paged_items(
                f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories",
                "repositories",
                params={"pageSize": 1000},
            )
            for item in items:
                if item.get("name"):
                    targets.append(
                        self.normalize_resource(item["name"], source="Artifact Registry list")
                    )
        return targets

    def _discover_pubsub(self, project: str, collection: str) -> List[dict]:
        return [
            self.normalize_resource(item.get("name", ""), source=f"Pub/Sub {collection} list")
            for item in self._paged_items(
                f"https://pubsub.googleapis.com/v1/projects/{project}/{collection}",
                collection,
                params={"pageSize": 1000},
            )
            if item.get("name")
        ]

    def _discover_bigquery(self, project: str) -> List[dict]:
        targets = []
        for item in self._paged_items(
            f"https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets",
            "datasets",
            params={"all": "true", "maxResults": 1000},
        ):
            reference = item.get("datasetReference") or {}
            dataset_id = reference.get("datasetId")
            dataset_project = reference.get("projectId") or project
            if dataset_id:
                targets.append(
                    self.normalize_resource(
                        f"//bigquery.googleapis.com/projects/{dataset_project}/datasets/{dataset_id}",
                        source="BigQuery list",
                    )
                )
        return targets

    def _discover_workflows(self, project: str) -> List[dict]:
        return [
            self.normalize_resource(item.get("name", ""), source="Workflows list")
            for item in self._paged_items(
                f"https://workflows.googleapis.com/v1/projects/{project}/locations/-/workflows",
                "workflows",
                params={"pageSize": 1000},
            )
            if item.get("name")
        ]

    def _discover_project_resources(self, project: str) -> List[dict]:
        targets = self._discover_assets(project)
        discoverers = [
            ("Compute Engine", self._discover_compute, (project,)),
            ("Cloud Functions v1", self._discover_functions, (project, "v1")),
            ("Cloud Functions v2", self._discover_functions, (project, "v2")),
            ("Cloud Storage", self._discover_storage, (project,)),
            ("service accounts", self._discover_service_accounts, (project,)),
            ("Secret Manager", self._discover_secrets, (project,)),
            ("Cloud Run services", self._discover_run, (project, "services")),
            ("Pub/Sub topics", self._discover_pubsub, (project, "topics")),
            ("Pub/Sub subscriptions", self._discover_pubsub, (project, "subscriptions")),
            ("BigQuery", self._discover_bigquery, (project,)),
            ("Workflows", self._discover_workflows, (project,)),
        ]
        # Location-bound APIs are expensive to sweep. A successful Cloud Asset
        # search already covers them; otherwise enumerate every advertised
        # location as the permissionless fallback.
        if project not in self._asset_inventory_success:
            discoverers.extend(
                [
                    ("Cloud Run jobs", self._discover_run, (project, "jobs")),
                    ("Artifact Registry", self._discover_artifacts, (project,)),
                ]
            )
        with ThreadPoolExecutor(max_workers=min(self.num_threads, len(discoverers))) as executor:
            futures = {
                executor.submit(function, *arguments): label
                for label, function, arguments in discoverers
            }
            for future in as_completed(futures):
                label = futures[future]
                try:
                    targets.extend(target for target in future.result() if target)
                except GCPApiError as exc:
                    self._record_failure(label, project, exc)
                except Exception as exc:
                    self._record_failure(
                        label,
                        project,
                        GCPApiError(None, str(exc), label, type(exc).__name__),
                    )
        return targets

    @staticmethod
    def _deduplicate_targets(targets: Iterable[Optional[dict]]) -> List[dict]:
        result: Dict[Tuple[str, str], dict] = {}
        for target in targets:
            if not target:
                continue
            key = (target["type"], target["id"])
            existing = result.get(key)
            if existing is None or existing.get("source") != "explicit":
                result[key] = target
        order = {"organization": 0, "folder": 1, "project": 2}
        return sorted(
            result.values(), key=lambda item: (order.get(item["type"], 3), item["type"], item["id"])
        )

    # IAM policies and effective permissions ----------------------------

    def _policy_request(self, target: dict) -> Tuple[str, str, Optional[dict], Optional[dict]]:
        resource = target["id"]
        resource_type = target["type"]
        if resource_type in {"project", "folder", "organization"}:
            return (
                "POST",
                f"{CRM_API}/{resource}:getIamPolicy",
                None,
                {"options": {"requestedPolicyVersion": 3}},
            )
        if resource_type == "vm":
            return (
                "GET",
                f"https://compute.googleapis.com/compute/v1/{resource}/getIamPolicy",
                {"optionsRequestedPolicyVersion": 3},
                None,
            )
        if resource_type == "function":
            version = target.get("api_version") or "v2"
            return (
                "GET",
                f"https://cloudfunctions.googleapis.com/{version}/{resource}:getIamPolicy",
                {"options.requestedPolicyVersion": 3},
                None,
            )
        if resource_type == "storage":
            bucket = resource.rsplit("/", 1)[-1]
            return (
                "GET",
                f"https://storage.googleapis.com/storage/v1/b/{bucket}/iam",
                {"optionsRequestedPolicyVersion": 3},
                None,
            )
        if resource_type == "service_account":
            return (
                "POST",
                f"https://iam.googleapis.com/v1/{resource}:getIamPolicy",
                None,
                {"options": {"requestedPolicyVersion": 3}},
            )
        hosts = {
            "secret": "secretmanager.googleapis.com/v1",
            "run_service": "run.googleapis.com/v2",
            "run_job": "run.googleapis.com/v2",
            "artifact_repository": "artifactregistry.googleapis.com/v1",
            "pubsub_topic": "pubsub.googleapis.com/v1",
            "pubsub_subscription": "pubsub.googleapis.com/v1",
            "workflow": "workflows.googleapis.com/v1",
            "kms_keyring": "cloudkms.googleapis.com/v1",
            "kms_key": "cloudkms.googleapis.com/v1",
        }
        host = hosts.get(resource_type)
        if not host:
            raise ValueError(f"Unsupported resource type: {resource_type}")
        return (
            "GET",
            f"https://{host}/{resource}:getIamPolicy",
            {"options.requestedPolicyVersion": 3},
            None,
        )

    def get_iam_policy(self, target) -> Optional[dict]:
        if isinstance(target, str):
            target = self.normalize_resource(target)
        if not target:
            return None
        try:
            method, url, params, body = self._policy_request(target)
            return self.client.request(method, url, params=params, json=body)
        except GCPApiError as exc:
            if (
                target["type"] == "function"
                and not target.get("api_version")
                and exc.status in {400, 404}
            ):
                fallback = dict(target, api_version="v1")
                try:
                    method, url, params, body = self._policy_request(fallback)
                    return self.client.request(method, url, params=params, json=body)
                except GCPApiError as fallback_exc:
                    exc = fallback_exc
            self._record_failure("get IAM policy", target.get("project", "global"), exc)
            return None
        except ValueError:
            return None

    def get_permissions_from_role(self, role_name: str) -> List[str]:
        cached = self._role_permissions.get(role_name)
        if cached is not None:
            return list(cached)
        if not re.match(r"^(roles|projects/[^/]+/roles|organizations/[^/]+/roles)/[^/]+$", role_name):
            return []
        try:
            role = self.client.request("GET", f"{IAM_API}/{role_name}")
            permissions = sorted(set(role.get("includedPermissions") or []))
            with self._cache_lock:
                self._role_permissions[role_name] = permissions
            return permissions
        except GCPApiError as exc:
            if exc.status != 404:
                self._record_failure("get IAM role", "global", exc)
            return []

    def _member_applies(self, member: str) -> bool:
        member = (member or "").strip().lower()
        if member in {"allusers", "allauthenticatedusers"}:
            return True
        if member.startswith("deleted:"):
            member = member[len("deleted:") :].split("?uid=", 1)[0]
        email = self.email.lower()
        if email and member in {f"user:{email}", f"serviceaccount:{email}"}:
            return True
        if member.startswith("group:") and member.split(":", 1)[1] in {
            group.lower() for group in self.groups
        }:
            return True
        if email and "@" in email and member == f"domain:{email.rsplit('@', 1)[1]}":
            return True
        return False

    def _permissions_from_policy(self, policy: Optional[dict]) -> Tuple[List[str], bool]:
        permissions: Set[str] = set()
        owner_role = False
        for binding in (policy or {}).get("bindings", []):
            if binding.get("condition"):
                with self._cache_lock:
                    self._conditional_bindings_skipped += 1
                continue
            if not any(self._member_applies(member) for member in binding.get("members", [])):
                continue
            role = binding.get("role", "")
            owner_role = owner_role or role == "roles/owner"
            permissions.update(self.get_permissions_from_role(role))
        return sorted(permissions), owner_role

    def _test_request(
        self, target: dict, permissions: Sequence[str]
    ) -> Tuple[str, str, dict, Optional[dict]]:
        resource = target["id"]
        resource_type = target["type"]
        body = {"permissions": list(permissions)}
        if resource_type in {"project", "folder", "organization"}:
            return "POST", f"{CRM_API}/{resource}:testIamPermissions", {}, body
        if resource_type == "vm":
            return (
                "POST",
                f"https://compute.googleapis.com/compute/v1/{resource}/testIamPermissions",
                {},
                body,
            )
        if resource_type == "function":
            version = target.get("api_version") or "v2"
            return (
                "POST",
                f"https://cloudfunctions.googleapis.com/{version}/{resource}:testIamPermissions",
                {},
                body,
            )
        if resource_type == "storage":
            bucket = resource.rsplit("/", 1)[-1]
            return (
                "GET",
                f"https://storage.googleapis.com/storage/v1/b/{bucket}/iam/testPermissions",
                {"permissions": list(permissions)},
                None,
            )
        hosts = {
            "service_account": "iam.googleapis.com/v1",
            "secret": "secretmanager.googleapis.com/v1",
            "run_service": "run.googleapis.com/v2",
            "run_job": "run.googleapis.com/v2",
            "artifact_repository": "artifactregistry.googleapis.com/v1",
            "pubsub_topic": "pubsub.googleapis.com/v1",
            "pubsub_subscription": "pubsub.googleapis.com/v1",
            "bigquery_dataset": "bigquery.googleapis.com/bigquery/v2",
            "workflow": "workflows.googleapis.com/v1",
            "kms_keyring": "cloudkms.googleapis.com/v1",
            "kms_key": "cloudkms.googleapis.com/v1",
        }
        host = hosts.get(resource_type)
        if not host:
            raise ValueError(f"Unsupported resource type: {resource_type}")
        return "POST", f"https://{host}/{resource}:testIamPermissions", {}, body

    def check_permissions(self, target, permissions, verbose=False) -> List[str]:
        if isinstance(target, str):
            target = self.normalize_resource(target)
        if not target or not permissions:
            return []
        try:
            method, url, params, body = self._test_request(target, permissions)
            response = self.client.request(method, url, params=params, json=body)
            return sorted(set(response.get("permissions") or []))
        except GCPApiError as exc:
            if (
                target["type"] == "function"
                and not target.get("api_version")
                and exc.status in {400, 404}
            ):
                return self.check_permissions(dict(target, api_version="v1"), permissions, verbose)
            # A single inapplicable permission makes many endpoints reject the
            # whole batch. Bisect so valid permissions are still recovered.
            if exc.status == 400 and len(permissions) > 1:
                midpoint = len(permissions) // 2
                return sorted(
                    set(self.check_permissions(target, permissions[:midpoint], verbose))
                    | set(self.check_permissions(target, permissions[midpoint:], verbose))
                )
            if exc.status == 400 and len(permissions) == 1:
                with self._cache_lock:
                    self._invalid_permissions.setdefault(target["id"], set()).add(permissions[0])
            elif verbose:
                print(f"{Fore.YELLOW}{target['id']}: {exc}")
            return []

    def can_check_permissions(self, resource_id, permissions) -> bool:
        """Compatibility helper; an empty success still means the API works."""
        target = resource_id if isinstance(resource_id, dict) else self.normalize_resource(resource_id)
        if not target or not permissions:
            return False
        try:
            method, url, params, body = self._test_request(target, permissions[:1])
            self.client.request(method, url, params=params, json=body)
            return True
        except (GCPApiError, ValueError):
            return False

    def _enumerate_target(self, target: dict) -> CloudResource:
        if target["type"] == "bigquery_dataset":
            return self._enumerate_bigquery_dataset(target)
        policy_permissions: List[str] = []
        owner_role = False
        if not self.dont_get_iam_policies:
            policy_permissions, owner_role = self._permissions_from_policy(self.get_iam_policy(target))

        tested: Set[str] = set()
        if not self.skip_bruteforce:
            catalog = self._query_testable_permissions(target)
            chunks = list(_chunks(catalog))
            if chunks:
                workers = min(max(1, self.num_threads), 5, len(chunks))
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [
                        executor.submit(self.check_permissions, target, chunk) for chunk in chunks
                    ]
                    for future in as_completed(futures):
                        tested.update(future.result())

        permissions = sorted(set(policy_permissions) | tested)
        return CloudResource(
            resource_id=target["id"],
            name=target["id"].rsplit("/", 1)[-1],
            resource_type=target["type"],
            permissions=permissions,
            deny_perms=[],
            is_admin=owner_role or self._is_admin_gcp(permissions, target["type"]),
            discovery_source=target.get("source", ""),
        )

    def _enumerate_bigquery_dataset(self, target: dict) -> CloudResource:
        """Use safe capability probes because BigQuery datasets lack testIamPermissions."""
        resource = target["id"]
        permissions: Set[str] = set()
        dataset = {}
        if not self.dont_get_iam_policies or not self.skip_bruteforce:
            try:
                dataset = self.client.request(
                    "GET", f"https://bigquery.googleapis.com/bigquery/v2/{resource}"
                )
                if not self.skip_bruteforce:
                    permissions.add("bigquery.datasets.get")
            except GCPApiError as exc:
                self._record_failure("BigQuery dataset get", target.get("project", ""), exc)

        acl_roles = {
            "READER": "roles/bigquery.dataViewer",
            "WRITER": "roles/bigquery.dataEditor",
            "OWNER": "roles/bigquery.dataOwner",
        }
        for entry in dataset.get("access", []) if not self.dont_get_iam_policies else []:
            member = ""
            if entry.get("userByEmail"):
                member = f"user:{entry['userByEmail']}"
            elif entry.get("groupByEmail"):
                member = f"group:{entry['groupByEmail']}"
            elif entry.get("domain"):
                member = f"domain:{entry['domain']}"
            elif entry.get("iamMember"):
                member = entry["iamMember"]
            elif entry.get("specialGroup") == "allAuthenticatedUsers":
                member = "allAuthenticatedUsers"
            if member and self._member_applies(member):
                role = acl_roles.get(entry.get("role"), entry.get("role", ""))
                permissions.update(self.get_permissions_from_role(role))

        probes = {
            "bigquery.tables.list": f"https://bigquery.googleapis.com/bigquery/v2/{resource}/tables",
            "bigquery.routines.list": f"https://bigquery.googleapis.com/bigquery/v2/{resource}/routines",
            "bigquery.models.list": f"https://bigquery.googleapis.com/bigquery/v2/{resource}/models",
        }
        if not self.skip_bruteforce:
            for permission, url in probes.items():
                try:
                    self.client.request("GET", url, params={"maxResults": 1})
                    permissions.add(permission)
                except GCPApiError:
                    pass
        return CloudResource(
            resource_id=resource,
            name=resource.rsplit("/", 1)[-1],
            resource_type=target["type"],
            permissions=sorted(permissions),
            deny_perms=[],
            is_admin=False,
            discovery_source=target.get("source", ""),
            enumeration_note="BigQuery datasets use read-only capability probes; the API has no dataset testIamPermissions method.",
        )

    def _print_failure_summary(self) -> None:
        if not self._failures:
            return
        print(f"\n{Fore.YELLOW}Some optional discovery paths were unavailable (enumeration continued):")
        for project, entries in sorted(self._failures.items()):
            grouped = Counter(
                f"{operation} (HTTP {error.status})"
                if error.status
                else f"{operation} (network)"
                for operation, error in entries
            )
            labels = [
                f"{label}" + (f" x{count}" if count > 1 else "")
                for label, count in grouped.items()
            ]
            print(f"{Fore.YELLOW}  {project}: {', '.join(labels)}")
        print(
            f"{Fore.CYAN}  Fallback: pass known names with --project/--service-account/--resource; "
            "testIamPermissions itself does not require the corresponding list permission."
        )

    def get_resources_and_permissions(self):
        targets: List[Optional[dict]] = []

        # Explicit inputs survive even when every discovery API returns 403.
        for project in self.projects:
            targets.append(self.normalize_resource(f"projects/{project}", source="explicit"))
        for folder in self.folders:
            if not folder.isdigit():
                raise ValueError(f"Folder ID must be numeric: {folder}")
            targets.append(self.normalize_resource(f"folders/{folder}", source="explicit"))
        for organization in self.orgs:
            if not organization.isdigit():
                raise ValueError(f"Organization ID must be numeric: {organization}")
            targets.append(self.normalize_resource(f"organizations/{organization}", source="explicit"))
        for email in self.sas:
            if "@" not in email:
                raise ValueError(f"Service account must be an email address: {email}")
            targets.append(self.normalize_resource(f"service-account:{email}", source="explicit"))
        for value in self.explicit_resources:
            for resource in _csv(value):
                target = self.normalize_resource(resource, source="explicit")
                if not target:
                    raise ValueError(f"Unsupported --resource value: {resource}")
                targets.append(target)

        credential_project = getattr(self.credentials, "project_id", "") or ""
        quota_project = getattr(self.credentials, "quota_project_id", "") or ""
        inferred_projects = {
            value
            for value in (
                credential_project,
                quota_project,
                os.getenv("GOOGLE_CLOUD_PROJECT", ""),
                os.getenv("GCLOUD_PROJECT", ""),
                os.getenv("GCP_PROJECT", ""),
            )
            if value
        }
        if self.email.endswith("iam.gserviceaccount.com"):
            inferred_projects.add(self.email.split("@", 1)[1].split(".", 1)[0])
        if not self.only_specified:
            for project in sorted(inferred_projects):
                targets.append(
                    self.normalize_resource(
                        f"projects/{project}", source="credentials/environment"
                    )
                )

        metadata_targets = [] if self.only_specified else self.discover_metadata_targets()
        targets.extend(metadata_targets)

        print(f"{Fore.BLUE}Discovering projects, folders, and organizations...")
        discovered_projects = [] if self.only_specified else self.list_projects()
        for project in discovered_projects:
            targets.append(
                self.normalize_resource(f"projects/{project}", source="Resource Manager search")
            )
        for folder in ([] if self.only_specified else self.list_folders()):
            targets.append(
                self.normalize_resource(f"folders/{folder}", source="Resource Manager search")
            )
        for organization in ([] if self.only_specified else self.list_organizations()):
            targets.append(
                self.normalize_resource(
                    f"organizations/{organization}", source="Resource Manager search"
                )
            )

        projects_to_enumerate = set()
        if not self.only_specified:
            projects_to_enumerate.update(
                target.get("project")
                for target in targets
                if target and target.get("project") and target["type"] != "storage"
            )
        projects_to_enumerate.update(self.projects)
        projects_to_enumerate.update(discovered_projects)
        if not self.only_specified:
            projects_to_enumerate.update(inferred_projects)
            projects_to_enumerate.update(
                target.get("project")
                for target in metadata_targets
                if target and target.get("project")
            )
        projects_to_enumerate.discard("")
        projects_to_enumerate.discard("_")

        if projects_to_enumerate:
            print(
                f"{Fore.BLUE}Trying Cloud Asset Inventory and service-specific read-only lists "
                f"in {len(projects_to_enumerate)} project(s)..."
            )
            with ThreadPoolExecutor(
                max_workers=min(self.num_threads, len(projects_to_enumerate))
            ) as executor:
                futures = {
                    executor.submit(self._discover_project_resources, project): project
                    for project in sorted(projects_to_enumerate)
                }
                for future in tqdm(
                    as_completed(futures), total=len(futures), desc="Discovering project resources"
                ):
                    targets.extend(future.result())

        final_targets = self._deduplicate_targets(targets)
        counts = Counter(target["type"] for target in final_targets)
        if counts:
            summary = ", ".join(
                f"{count} {kind}" for kind, count in sorted(counts.items())
            )
            print(f"{Fore.GREEN}Targets found: {summary}")
        else:
            print(
                f"{Fore.YELLOW}No targets were discovered. Supply a known project or resource name; "
                "knowing its name is enough to attempt testIamPermissions."
            )
            self._print_failure_summary()
            return []

        if self.skip_bruteforce and self.dont_get_iam_policies:
            print(
                f"{Fore.YELLOW}Discovery-only mode: both permission tests and IAM policy reads "
                "were disabled."
            )
            self._print_failure_summary()
            return []

        print(
            f"{Fore.BLUE}Checking effective permissions on {len(final_targets)} target(s) "
            f"with read-only IAM calls..."
        )
        resources: List[CloudResource] = []
        target_workers = min(max(1, self.num_threads), len(final_targets))
        with ThreadPoolExecutor(max_workers=target_workers) as executor:
            futures = {
                executor.submit(self._enumerate_target, target): target for target in final_targets
            }
            for future in tqdm(
                as_completed(futures), total=len(futures), desc="Testing permissions"
            ):
                target = futures[future]
                try:
                    resources.append(future.result())
                except Exception as exc:
                    print(f"{Fore.YELLOW}Could not finish {target['id']}: {exc}")

        if self._conditional_bindings_skipped:
            print(
                f"{Fore.YELLOW}Skipped {self._conditional_bindings_skipped} conditional IAM binding(s) "
                "during policy parsing; testIamPermissions was used for the current effective result."
            )
        if self.print_invalid_perms and self._invalid_permissions:
            print(f"{Fore.YELLOW}Permissions rejected as inapplicable by resource APIs:")
            for resource, permissions in sorted(self._invalid_permissions.items()):
                print(f"{Fore.BLUE}  {resource}: {', '.join(sorted(permissions))}")
        self._print_failure_summary()
        return resources

    @staticmethod
    def _is_admin_gcp(permissions, resource_type):
        permission_set = {str(permission).lower() for permission in permissions}
        required = {
            "project": {"resourcemanager.projects.setiampolicy"},
            "folder": {"resourcemanager.folders.setiampolicy"},
            "organization": {"resourcemanager.organizations.setiampolicy"},
        }.get(resource_type)
        return bool(required and required.issubset(permission_set))

    # Principal information --------------------------------------------

    def get_user_groups(self) -> List[str]:
        """Try direct transitive group lookup; testIamPermissions is the fallback."""
        if not self.email or self.is_sa:
            return []
        groups: Set[str] = set()
        try:
            for page in self.client.iter_pages(
                "GET",
                "https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchTransitiveGroups",
                params={
                    "query": (
                        f"member_key_id == '{self.email}' && "
                        "'cloudidentity.googleapis.com/groups.discussion_forum' in labels"
                    ),
                    "pageSize": 1000,
                },
            ):
                for membership in page.get("memberships", []):
                    group_key = membership.get("groupKey") or {}
                    if group_key.get("id"):
                        groups.add(group_key["id"])
        except GCPApiError as exc:
            self._record_failure("Cloud Identity group lookup", "global", exc)
        return sorted(groups)

    def _inspect_token(self, token: str) -> dict:
        result = {"email": None, "expires_in": None, "audience": None, "scopes": []}
        if not token:
            return result
        try:
            response = requests.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": token},
                timeout=self.client.timeout,
                proxies=(
                    {"http": self.client.proxy, "https": self.client.proxy}
                    if self.client.proxy
                    else None
                ),
                verify=self.client.verify_tls,
            )
            if response.status_code == 200:
                raw = response.json()
                result.update(
                    {
                        "email": raw.get("email"),
                        "expires_in": raw.get("expires_in"),
                        "audience": raw.get("audience") or raw.get("aud"),
                        "scopes": (raw.get("scope") or "").split(),
                    }
                )
        except (requests.RequestException, ValueError):
            pass
        return result

    def print_whoami_info(self, use_extra=False):
        if not use_extra and not getattr(self.credentials, "valid", False):
            try:
                self.credentials.refresh(Request())
            except Exception as exc:
                print(f"{Fore.YELLOW}Could not refresh credentials before token inspection: {exc}")

        token = self.extra_token if use_extra else getattr(self.credentials, "token", "")
        user_info = self._inspect_token(token)
        user_info["cloud"] = "gcp"
        if not user_info.get("email"):
            user_info["email"] = (
                getattr(self.credentials, "service_account_email", None)
                or getattr(self.credentials, "target_principal", None)
            )
        if not user_info.get("scopes"):
            user_info["scopes"] = list(getattr(self.credentials, "scopes", None) or [])
        user_info["credential_type"] = type(self.credentials).__name__
        user_info["quota_project"] = getattr(self.credentials, "quota_project_id", None)

        if user_info.get("email") and not use_extra:
            self.email = user_info["email"]
            self.is_sa = self.email.endswith("iam.gserviceaccount.com")
            kind = "service account" if self.is_sa else "user/workforce principal"
            print(f"{Fore.BLUE}Current principal: {Fore.WHITE}{self.email} {Fore.CYAN}({kind})")
            self.groups = self.get_user_groups()
            if self.groups:
                print(f"{Fore.BLUE}Known transitive groups: {Fore.WHITE}{', '.join(self.groups)}")
        elif not use_extra:
            print(
                f"{Fore.YELLOW}The token did not expose an email. Effective permissions will still be "
                "enumerated with testIamPermissions."
            )
        if user_info.get("expires_in"):
            print(f"{Fore.BLUE}Token expires in: {Fore.WHITE}{user_info['expires_in']} seconds")
        if user_info.get("audience"):
            print(f"{Fore.BLUE}Token audience: {Fore.WHITE}{user_info['audience']}")
        if user_info.get("scopes"):
            print(f"{Fore.BLUE}OAuth scopes: {Fore.WHITE}{', '.join(user_info['scopes'])}")
            workspace = [
                scope
                for scope in user_info["scopes"]
                if "/gmail" in scope or "/drive" in scope
            ]
            if workspace:
                print(
                    f"{Fore.GREEN}Workspace-capable scope(s) detected; GCPPEASS does not read mailbox "
                    "or Drive content automatically."
                )
        if self.extra_token and not use_extra and self.extra_token != token:
            user_info["extra_token"] = self.print_whoami_info(True)
        return user_info


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "GCPPEASS: enumerate effective GCP permissions and privilege-escalation risk "
            "using read-only API calls. No cloud resource is created, changed, executed, or deleted."
        )
    )
    parser.add_argument(
        "--projects", "--project", dest="projects", help="Known project IDs, comma-separated"
    )
    parser.add_argument(
        "--folders", "--folder", dest="folders", help="Known numeric folder IDs, comma-separated"
    )
    parser.add_argument(
        "--organizations",
        "--organization",
        dest="organizations",
        help="Known numeric organization IDs, comma-separated",
    )
    parser.add_argument(
        "--service-accounts",
        "--service-account",
        dest="service_accounts",
        help="Known service account emails, comma-separated",
    )
    parser.add_argument(
        "--resource",
        "--resources",
        dest="resources",
        action="append",
        default=[],
        help=(
            "Known resource name; repeat the option or use commas. Accepts full //service/name "
            "names, canonical projects/... names, gs://bucket, bucket:NAME, and service-account:EMAIL"
        ),
    )

    parser.add_argument(
        "--sa-credentials-path",
        help="Service account JSON path (or GOOGLE_APPLICATION_CREDENTIALS)",
    )
    parser.add_argument("--token", help="Raw access token (or CLOUDSDK_AUTH_ACCESS_TOKEN)")
    parser.add_argument(
        "--extra-token", help="Optional second token whose identity/scopes should be inspected"
    )
    parser.add_argument(
        "--dont-get-iam-policies",
        "--skip-iam-policies",
        dest="dont_get_iam_policies",
        action="store_true",
        help="Skip IAM policy reads and rely on testIamPermissions",
    )
    parser.add_argument(
        "--skip-bruteforce",
        action="store_true",
        help="Skip testIamPermissions (less complete; policy read permissions are usually required)",
    )
    parser.add_argument(
        "--skip-asset-inventory",
        action="store_true",
        help="Skip Cloud Asset Inventory and use service-specific list fallbacks only",
    )
    parser.add_argument(
        "--only-specified",
        action="store_true",
        help="Do not search for additional containers; scan only supplied projects/resources",
    )
    parser.add_argument(
        "--no-ask",
        action="store_true",
        help="Compatibility flag; GCPPEASS is now non-interactive",
    )
    parser.add_argument("--out-json-path", default=None, help="Write analysis JSON here")
    parser.add_argument("--threads", default=5, type=int, help="Maximum worker count (default: 5)")
    parser.add_argument(
        "--billing-project", default="", help="Quota project for API calls (does not modify billing)"
    )
    parser.add_argument(
        "--proxy", default="", help="HTTP proxy, for example 127.0.0.1:8080"
    )
    parser.add_argument(
        "--timeout", default=20, type=float, help="Per-request timeout in seconds (default: 20)"
    )
    parser.add_argument(
        "--retries",
        default=3,
        type=int,
        help="Retries for rate limits and transient errors (default: 3)",
    )
    parser.add_argument(
        "--insecure", action="store_true", help="Disable TLS verification (proxy debugging only)"
    )
    parser.add_argument("--debug", action="store_true", help="Show individual API failures")
    parser.add_argument(
        "--print-invalid-permissions",
        action="store_true",
        help="Print catalog permissions rejected as inapplicable by an API",
    )
    return parser


def _load_credentials(args, parser):
    token = (args.token or os.getenv("CLOUDSDK_AUTH_ACCESS_TOKEN") or "").strip()
    credentials_path = args.sa_credentials_path or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if args.token and args.sa_credentials_path:
        parser.error("Use only one of --token and --sa-credentials-path")
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    try:
        if token:
            return google.oauth2.credentials.Credentials(token)
        if credentials_path:
            return google.oauth2.service_account.Credentials.from_service_account_file(
                credentials_path, scopes=scopes
            )
        credentials, _ = google.auth.default(scopes=scopes)
        return credentials
    except Exception as exc:
        parser.error(
            "No usable credentials found. Pass --token/--sa-credentials-path, set the matching "
            f"environment variable, or configure Application Default Credentials ({exc})."
        )


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    credentials = _load_credentials(args, parser)
    peass = GCPPEASS(
        credentials,
        args.extra_token or os.getenv("GCP_EXTRA_TOKEN"),
        args.projects,
        args.folders,
        args.organizations,
        args.service_accounts,
        very_sensitive_combinations,
        sensitive_combinations,
        num_threads=args.threads,
        out_path=args.out_json_path,
        billing_project=args.billing_project,
        proxy=args.proxy,
        print_invalid_perms=args.print_invalid_permissions,
        dont_get_iam_policies=args.dont_get_iam_policies,
        skip_bruteforce=args.skip_bruteforce,
        no_ask=args.no_ask,
        resources=args.resources,
        skip_asset_inventory=args.skip_asset_inventory,
        timeout=args.timeout,
        retries=args.retries,
        insecure=args.insecure,
        debug=args.debug,
        only_specified=args.only_specified,
    )
    peass.run_analysis()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
