import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from GCPPEAS import GCPPEASS
from src.CloudPEASS.cloudpeass import CloudResource
from src.gcp.client import GCPApiError, GCPReadOnlyClient


def bare_peass():
    peass = object.__new__(GCPPEASS)
    peass.debug = False
    peass.email = "alice@example.com"
    peass.is_sa = False
    peass.groups = ["redteam@example.com"]
    peass._role_permissions = {
        "roles/viewer": ["resourcemanager.projects.get"],
        "roles/bigquery.dataViewer": ["bigquery.tables.getData"],
    }
    peass._cache_lock = threading.Lock()
    peass._failures = {}
    peass._conditional_bindings_skipped = 0
    peass._invalid_permissions = {}
    peass.print_invalid_perms = False
    peass.skip_bruteforce = False
    peass.dont_get_iam_policies = False
    return peass


@pytest.mark.parametrize(
    "value,expected_type,expected_id",
    [
        ("project:demo-project", "project", "projects/demo-project"),
        ("folder:1234", "folder", "folders/1234"),
        ("gs://demo-bucket/path", "storage", "projects/_/buckets/demo-bucket"),
        (
            "service-account:runner@demo-project.iam.gserviceaccount.com",
            "service_account",
            "projects/demo-project/serviceAccounts/runner@demo-project.iam.gserviceaccount.com",
        ),
        (
            "//compute.googleapis.com/projects/demo-project/zones/us-central1-a/instances/vm-1",
            "vm",
            "projects/demo-project/zones/us-central1-a/instances/vm-1",
        ),
        (
            "projects/demo-project/locations/us-central1/secrets/key",
            "secret",
            "projects/demo-project/locations/us-central1/secrets/key",
        ),
        (
            "projects/demo-project/locations/us-central1/services/api",
            "run_service",
            "projects/demo-project/locations/us-central1/services/api",
        ),
        (
            "projects/demo-project/locations/us/repositories/images",
            "artifact_repository",
            "projects/demo-project/locations/us/repositories/images",
        ),
        (
            "projects/demo-project/topics/events",
            "pubsub_topic",
            "projects/demo-project/topics/events",
        ),
        (
            "projects/demo-project/datasets/warehouse",
            "bigquery_dataset",
            "projects/demo-project/datasets/warehouse",
        ),
    ],
)
def test_normalize_resource_formats(value, expected_type, expected_id):
    target = bare_peass().normalize_resource(value)
    assert target["type"] == expected_type
    assert target["id"] == expected_id
    assert target["full_name"].startswith("//")


def test_function_generation_can_be_explicit():
    peass = bare_peass()
    target = peass.normalize_resource(
        "function-v2:projects/demo-project/locations/us-central1/functions/fn"
    )
    assert target["api_version"] == "v2"


@pytest.mark.parametrize(
    "value,asset_type",
    [
        (
            "//iam.googleapis.com/projects/p/serviceAccounts/123/keys/key-id",
            "iam.googleapis.com/ServiceAccountKey",
        ),
        (
            "//cloudkms.googleapis.com/projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "cloudkms.googleapis.com/CryptoKeyVersion",
        ),
        (
            "//serviceusage.googleapis.com/projects/123/services/run.googleapis.com",
            "serviceusage.googleapis.com/Service",
        ),
        (
            "//appengine.googleapis.com/projects/p/locations/l/applications/p/services/default/versions/v1",
            "appengine.googleapis.com/Version",
        ),
    ],
)
def test_child_or_unhandled_assets_are_not_misclassified(value, asset_type):
    assert bare_peass().normalize_resource(value, asset_type=asset_type) is None


def test_member_matching_is_exact_and_supports_common_principals():
    peass = bare_peass()
    assert peass._member_applies("user:alice@example.com")
    assert peass._member_applies("group:redteam@example.com")
    assert peass._member_applies("domain:example.com")
    assert peass._member_applies("allUsers")
    assert peass._member_applies("allAuthenticatedUsers")
    assert not peass._member_applies("user:malice@example.com")
    assert not peass._member_applies("user:alice@example.com.attacker")


def test_policy_parser_skips_conditions_instead_of_overstating_access():
    peass = bare_peass()
    policy = {
        "bindings": [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]},
            {
                "role": "roles/owner",
                "members": ["user:alice@example.com"],
                "condition": {"expression": "request.time < timestamp('2000-01-01T00:00:00Z')"},
            },
        ]
    }
    permissions, owner = peass._permissions_from_policy(policy)
    assert permissions == ["resourcemanager.projects.get"]
    assert owner is False
    assert peass._conditional_bindings_skipped == 1


def test_read_only_transport_blocks_mutating_endpoints():
    GCPReadOnlyClient._assert_read_only("GET", "https://example.googleapis.com/v1/projects/p")
    GCPReadOnlyClient._assert_read_only(
        "POST", "https://example.googleapis.com/v1/projects/p:testIamPermissions"
    )
    GCPReadOnlyClient._assert_read_only(
        "POST", "https://example.googleapis.com/v1/projects/p:getIamPolicy"
    )
    with pytest.raises(ValueError, match="Blocked non-read-only"):
        GCPReadOnlyClient._assert_read_only(
            "POST", "https://serviceusage.googleapis.com/v1/projects/p/services/x:enable"
        )
    with pytest.raises(ValueError, match="Blocked non-read-only"):
        GCPReadOnlyClient._assert_read_only(
            "POST", "https://run.googleapis.com/v2/projects/p/locations/l/jobs/j:run"
        )
    with pytest.raises(ValueError, match="Blocked non-read-only"):
        GCPReadOnlyClient._assert_read_only(
            "DELETE", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"
        )


def test_iter_pages_keeps_body_and_follows_tokens():
    client = object.__new__(GCPReadOnlyClient)
    calls = []
    responses = iter([{"items": [1], "nextPageToken": "next"}, {"items": [2]}])

    def request(method, url, params=None, json=None):
        calls.append((dict(params or {}), dict(json or {})))
        return next(responses)

    client.request = request
    body = {"pageSize": 10}
    pages = list(client.iter_pages("POST", "https://x/v1/x:search", json=body, token_in_body=True))
    assert [page["items"] for page in pages] == [[1], [2]]
    assert calls[1][1]["pageToken"] == "next"
    assert body == {"pageSize": 10}


def test_cloud_run_service_discovery_follows_knative_continue_token():
    peass = bare_peass()
    calls = []
    pages = iter(
        [
            {
                "items": [
                    {
                        "metadata": {
                            "name": "first",
                            "labels": {"cloud.googleapis.com/location": "us-central1"},
                        }
                    }
                ],
                "metadata": {"continue": "opaque-token"},
            },
            {
                "items": [
                    {
                        "metadata": {
                            "name": "second",
                            "labels": {"cloud.googleapis.com/location": "europe-west1"},
                        }
                    }
                ]
            },
        ]
    )

    def request(method, url, params=None, json=None):
        calls.append(dict(params or {}))
        return next(pages)

    peass.client = SimpleNamespace(request=request)
    targets = peass._discover_run("demo-project", "services")
    assert [target["id"] for target in targets] == [
        "projects/demo-project/locations/us-central1/services/first",
        "projects/demo-project/locations/europe-west1/services/second",
    ]
    assert calls[1]["continue"] == "opaque-token"


def test_invalid_permission_bisection_preserves_valid_results():
    peass = bare_peass()
    peass._invalid_permissions = {}
    target = peass.normalize_resource("projects/demo-project")

    def request(method, url, params=None, json=None):
        permissions = json["permissions"]
        if "invalid.permission" in permissions:
            raise GCPApiError(400, "Permission is not valid", url)
        return {"permissions": [p for p in permissions if p == "resourcemanager.projects.get"]}

    peass.client = SimpleNamespace(request=request)
    found = peass.check_permissions(
        target,
        ["resourcemanager.projects.get", "invalid.permission", "resourcemanager.projects.delete"],
    )
    assert found == ["resourcemanager.projects.get"]
    assert peass._invalid_permissions[target["id"]] == {"invalid.permission"}


def test_only_specified_project_survives_denied_discovery():
    peass = bare_peass()
    peass.projects = ["known-project"]
    peass.folders = []
    peass.orgs = []
    peass.sas = []
    peass.explicit_resources = []
    peass.only_specified = True
    peass.num_threads = 1
    peass.credentials = SimpleNamespace(project_id=None, quota_project_id=None)
    peass.discover_metadata_targets = Mock(side_effect=AssertionError("metadata should be skipped"))
    peass.list_projects = Mock(side_effect=AssertionError("project search should be skipped"))
    peass.list_folders = Mock(side_effect=AssertionError("folder search should be skipped"))
    peass.list_organizations = Mock(side_effect=AssertionError("org search should be skipped"))
    peass._discover_project_resources = Mock(return_value=[])
    peass._print_failure_summary = Mock()
    peass._enumerate_target = lambda target: CloudResource(
        target["id"], target["id"], target["type"], ["resourcemanager.projects.get"]
    )
    resources = peass.get_resources_and_permissions()
    assert [resource.id for resource in resources] == ["projects/known-project"]


def test_bigquery_dataset_uses_read_only_capability_probes():
    peass = bare_peass()
    target = peass.normalize_resource("projects/demo-project/datasets/data")
    seen = []

    def request(method, url, params=None, json=None):
        seen.append((method, url))
        if url.endswith("datasets/data"):
            return {
                "access": [
                    {"role": "READER", "userByEmail": "alice@example.com"},
                    {"role": "OWNER", "userByEmail": "someone@example.com"},
                ]
            }
        return {}

    peass.client = SimpleNamespace(request=request)
    peass.dont_get_iam_policies = False
    peass.skip_bruteforce = False
    resource = peass._enumerate_bigquery_dataset(target)
    assert "bigquery.datasets.get" in resource.permissions
    assert "bigquery.tables.getData" in resource.permissions
    assert "bigquery.tables.list" in resource.permissions
    assert all(method == "GET" for method, _ in seen)
