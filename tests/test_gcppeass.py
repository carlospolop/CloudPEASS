import threading
import ast
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from GCPPEAS import (
    BUILTIN_FALLBACK_PERMISSIONS,
    TYPE_PREFIXES,
    GCPPEASS,
    _build_parser,
    _validate_args,
)
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
    peass._failures = defaultdict(list)
    peass._permission_test_failure_keys = set()
    peass._conditional_bindings_skipped = 0
    peass._invalid_permissions = {}
    peass.print_invalid_perms = False
    peass.skip_bruteforce = False
    peass.dont_get_iam_policies = False
    peass.num_threads = 2
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
        (
            "projects/demo-project/datasets/warehouse/tables/customers",
            "bigquery_table",
            "projects/demo-project/datasets/warehouse/tables/customers",
        ),
        (
            "projects/demo-project/datasets/warehouse/routines/transform",
            "bigquery_routine",
            "projects/demo-project/datasets/warehouse/routines/transform",
        ),
        (
            "projects/demo-project/snapshots/recovery",
            "pubsub_snapshot",
            "projects/demo-project/snapshots/recovery",
        ),
        (
            "dns-zone:projects/demo-project/managedZones/public-zone",
            "dns_zone",
            "projects/demo-project/managedZones/public-zone",
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
    assert bare_peass().normalize_resource(
        "function-v1:projects/demo-project/locations/us-central1/functions/fn"
    )["api_version"] == "v1"


def test_full_resource_name_rejects_mismatched_service_host():
    peass = bare_peass()
    assert peass.normalize_resource("//evil.example/projects/demo-project") is None
    assert peass.normalize_resource(
        "//storage.googleapis.com/projects/demo-project"
    ) is None


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


def test_group_lookup_uses_transitive_api_when_available():
    peass = bare_peass()
    calls = []

    def iter_pages(method, url, params=None, **kwargs):
        calls.append((url, dict(params or {})))
        return iter(
            [
                {
                    "memberships": [
                        {"groupKey": {"id": "parent@example.com"}},
                        {"groupKey": {"id": "direct@example.com"}},
                    ]
                }
            ]
        )

    peass.client = SimpleNamespace(iter_pages=iter_pages)
    assert peass.get_user_groups() == ["direct@example.com", "parent@example.com"]
    assert len(calls) == 1
    assert calls[0][0].endswith(":searchTransitiveGroups")


def test_group_lookup_falls_back_to_direct_and_walks_visible_parents():
    peass = bare_peass()
    calls = []

    def iter_pages(method, url, params=None, **kwargs):
        params = dict(params or {})
        calls.append((url, params))
        if url.endswith(":searchTransitiveGroups"):
            raise GCPApiError(403, "Premium feature unavailable", url, "PERMISSION_DENIED")
        query = params["query"]
        if query == 'member_key_id == "alice@example.com"':
            return iter(
                [
                    {
                        "memberships": [
                            {"groupKey": {"id": "direct@example.com"}},
                            {"groupKey": {"id": "external@other.example"}},
                        ]
                    }
                ]
            )
        if query == 'member_key_id == "direct@example.com"':
            return iter(
                [{"memberships": [{"groupKey": {"id": "parent@example.com"}}]}]
            )
        return iter([{}])

    peass.client = SimpleNamespace(iter_pages=iter_pages)
    assert peass.get_user_groups() == [
        "direct@example.com",
        "external@other.example",
        "parent@example.com",
    ]
    direct_calls = [call for call in calls if call[0].endswith(":searchDirectGroups")]
    assert len(direct_calls) == 4
    assert all("labels" not in call[1]["query"] for call in direct_calls)
    assert peass._failures == {}


def test_group_lookup_reports_failure_only_when_both_paths_are_unavailable():
    peass = bare_peass()

    def unavailable(method, url, **kwargs):
        raise GCPApiError(403, "API disabled or caller denied", url, "PERMISSION_DENIED")

    peass.client = SimpleNamespace(iter_pages=unavailable)
    assert peass.get_user_groups() == []
    assert list(peass._failures) == ["global"]
    operation, error = peass._failures["global"][0]
    assert operation == "Cloud Identity group lookup"
    assert error.status == 403


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
    with pytest.raises(ValueError, match="non-Google or non-HTTPS"):
        GCPReadOnlyClient._assert_read_only("GET", "http://iam.googleapis.com/v1/roles")
    with pytest.raises(ValueError, match="non-Google or non-HTTPS"):
        GCPReadOnlyClient._assert_read_only("GET", "https://example.com/v1/roles")


@pytest.mark.parametrize(
    "resource",
    [
        "projects/demo-project",
        "folders/123",
        "organizations/456",
        "projects/demo-project/zones/us-central1-a/instances/vm",
        "function-v1:projects/demo-project/locations/us-central1/functions/fn1",
        "function-v2:projects/demo-project/locations/us-central1/functions/fn2",
        "gs://bucket-name",
        "service-account:sa@demo-project.iam.gserviceaccount.com",
        "projects/demo-project/secrets/global-secret",
        "projects/demo-project/locations/europe-west1/secrets/regional-secret",
        "projects/demo-project/locations/us-central1/services/service",
        "projects/demo-project/locations/us-central1/jobs/job",
        "projects/demo-project/locations/us/repositories/repository",
        "projects/demo-project/topics/topic",
        "projects/demo-project/subscriptions/subscription",
        "projects/demo-project/snapshots/snapshot",
        "projects/demo-project/datasets/dataset/tables/table",
        "projects/demo-project/datasets/dataset/routines/routine",
        "projects/demo-project/locations/us-central1/workflows/workflow",
        "projects/demo-project/locations/global/keyRings/ring",
        "projects/demo-project/locations/global/keyRings/ring/cryptoKeys/key",
        "projects/demo-project/managedZones/public-zone",
    ],
)
def test_every_resource_request_builder_passes_the_transport_guard(resource):
    peass = bare_peass()
    target = peass.normalize_resource(resource)
    for builder_args in ((peass._policy_request, (target,)), (peass._test_request, (target, ["x.y"]))):
        builder, arguments = builder_args
        method, url, _, _ = builder(*arguments)
        GCPReadOnlyClient._assert_read_only(method, url)


def test_gcppeass_has_no_raw_mutating_http_or_process_execution_calls():
    source = Path(__file__).resolve().parents[1] / "GCPPEAS.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    forbidden = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if isinstance(owner, ast.Name) and owner.id == "requests":
            if node.func.attr not in {"get", "Session"}:
                forbidden.append(f"requests.{node.func.attr}")
        if isinstance(owner, ast.Name) and owner.id in {"os", "subprocess"}:
            if node.func.attr in {"system", "popen", "run", "call", "check_call", "check_output"}:
                forbidden.append(f"{owner.id}.{node.func.attr}")
    assert forbidden == []


def test_proxy_validation_and_retry_after_are_bounded():
    assert GCPReadOnlyClient._normalize_proxy("127.0.0.1:8080") == "http://127.0.0.1:8080"
    with pytest.raises(ValueError, match="numeric port"):
        GCPReadOnlyClient._normalize_proxy("127.0.0.1:not-a-port")
    assert GCPReadOnlyClient._retry_delay("-20", 0) == 0
    assert GCPReadOnlyClient._retry_delay("999", 0) == 30
    assert GCPApiError(None, "expired", "https://iam.googleapis.com", "auth:RefreshError").category == "authentication"


@pytest.mark.parametrize(
    "arguments",
    [
        ["--folder", "not-numeric"],
        ["--organization", "123/child"],
        ["--project", "projects/bad"],
        ["--service-account", "user@example.com"],
        ["--threads", "0"],
        ["--threads", "257"],
        ["--timeout", "nan"],
        ["--retries", "11"],
    ],
)
def test_invalid_cli_values_fail_before_authentication(arguments):
    parser = _build_parser()
    args = parser.parse_args(arguments)
    with pytest.raises(SystemExit) as error:
        _validate_args(args, parser)
    assert error.value.code == 2


def test_invalid_output_paths_fail_before_authentication(tmp_path):
    parser = _build_parser()
    for invalid in (tmp_path, tmp_path / "missing" / "results.json"):
        args = parser.parse_args(["--out-json-path", str(invalid)])
        with pytest.raises(SystemExit) as error:
            _validate_args(args, parser)
        assert error.value.code == 2


def test_valid_output_path_passes_pre_authentication_validation(tmp_path):
    parser = _build_parser()
    args = parser.parse_args(["--out-json-path", str(tmp_path / "results.json")])
    _validate_args(args, parser)


def test_builtin_fallback_covers_every_modern_resource_type():
    legacy_types = {"vm", "function", "storage"}
    for resource_type, prefixes in TYPE_PREFIXES.items():
        if resource_type in legacy_types:
            continue
        assert any(
            permission.startswith(prefixes)
            for permission in BUILTIN_FALLBACK_PERMISSIONS
        ), resource_type


def test_workflow_fallback_uses_current_permission_namespace():
    assert "workflows.executions.create" in BUILTIN_FALLBACK_PERMISSIONS
    assert TYPE_PREFIXES["workflow"] == (
        "workflows.workflows.",
        "workflows.executions.",
    )


def test_dns_fallback_covers_workspace_recovery_permission_pair():
    assert TYPE_PREFIXES["dns_zone"] == ("dns.",)
    assert {
        "dns.changes.create",
        "dns.resourceRecordSets.create",
        "dns.resourceRecordSets.update",
        "dns.resourceRecordSets.delete",
    } <= BUILTIN_FALLBACK_PERMISSIONS


def test_testable_catalog_drops_cross_service_permissions():
    peass = bare_peass()
    peass._testable_cache = {}
    peass.client = SimpleNamespace(
        iter_pages=lambda *args, **kwargs: iter(
            [
                {
                    "permissions": [
                        {"name": "storage.buckets.get"},
                        {"name": "storage.objects.list"},
                        {"name": "resourcemanager.hierarchyNodes.createTagBinding"},
                    ]
                }
            ]
        )
    )
    target = peass.normalize_resource("gs://bucket", project_hint="demo-project")
    assert peass._query_testable_permissions(target) == [
        "storage.buckets.get",
        "storage.objects.list",
    ]


def test_catalog_loader_uses_modern_builtin_fallback(monkeypatch):
    peass = bare_peass()

    def unavailable(*args, **kwargs):
        raise GCPApiError(503, "unavailable", "https://iam.googleapis.com/v1/roles")

    def public_unavailable(*args, **kwargs):
        raise __import__("requests").ConnectionError("offline")

    peass.client = SimpleNamespace(
        iter_pages=unavailable,
        proxy="",
        timeout=1,
        verify_tls=True,
    )
    monkeypatch.setattr("GCPPEAS.requests.get", public_unavailable)
    catalog = set(peass._load_permission_catalog())
    assert BUILTIN_FALLBACK_PERMISSIONS <= catalog


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


def test_cloud_dns_zone_discovery_and_read_only_request_builders():
    peass = bare_peass()
    peass._paged_items = Mock(
        return_value=[
            {"name": "public-zone", "dnsName": "example.com."},
            {"dnsName": "missing-name.example."},
        ]
    )
    targets = peass._discover_dns_zones("demo-project")
    assert [target["id"] for target in targets] == [
        "projects/demo-project/managedZones/public-zone"
    ]
    target = targets[0]
    policy_method, policy_url, _, _ = peass._policy_request(target)
    test_method, test_url, _, body = peass._test_request(
        target, ["dns.changes.create"]
    )
    assert policy_method == test_method == "POST"
    assert policy_url.endswith(
        "/dns/v1/projects/demo-project/managedZones/public-zone:getIamPolicy"
    )
    assert test_url.endswith(
        "/dns/v1/projects/demo-project/managedZones/public-zone:testIamPermissions"
    )
    assert body == {"permissions": ["dns.changes.create"]}


def test_cross_cloud_notes_cover_validated_workspace_trust_edges():
    peass = bare_peass()
    project = peass.normalize_resource("projects/demo-project")
    assert peass._cross_cloud_pivot_notes(
        project, ["dns.resourceRecordSets.create"]
    ) == []
    dns_notes = peass._cross_cloud_pivot_notes(
        project,
        ["dns.changes.create", "dns.resourceRecordSets.create"],
    )
    assert len(dns_notes) == 1
    assert "administrator-recovery" in dns_notes[0]
    policy_notes = peass._cross_cloud_pivot_notes(
        project, ["dns.managedZones.setIamPolicy"]
    )
    assert len(policy_notes) == 1
    assert "roles/dns.admin" in policy_notes[0]

    sa = peass.normalize_resource(
        "service-account:runner@demo-project.iam.gserviceaccount.com"
    )
    sa_notes = peass._cross_cloud_pivot_notes(
        sa, ["iam.serviceAccounts.signJwt"]
    )
    assert len(sa_notes) == 2
    assert any("Direct sharing does not require" in note for note in sa_notes)
    assert any("domain-wide delegation" in note for note in sa_notes)

    access_token_notes = peass._cross_cloud_pivot_notes(
        sa, ["iam.serviceAccounts.getAccessToken"]
    )
    assert len(access_token_notes) == 1
    assert "Drive files/folders or calendars" in access_token_notes[0]
    assert peass._cross_cloud_pivot_notes(
        project, ["iam.serviceAccounts.signJwt"]
    ) == []

    federation_notes = peass._cross_cloud_pivot_notes(
        project, ["iam.googleapis.com/workloadIdentityPoolProviders.update"]
    )
    assert len(federation_notes) == 1
    assert "Critical federation privilege escalation" in federation_notes[0]
    assert "overlap" in federation_notes[0]
    assert "Google STS" in federation_notes[0]

    organization = peass.normalize_resource("organizations/123456789")
    organization_notes = peass._cross_cloud_pivot_notes(
        organization, ["resourcemanager.organizations.setIamPolicy"]
    )
    assert len(organization_notes) == 1
    assert "roles/resourcemanager.organizationAdmin" in organization_notes[0]
    assert "listing and policy visibility are not prerequisites" in organization_notes[0]

    peass.is_sa = True
    assert peass._cross_cloud_pivot_notes(
        organization, ["resourcemanager.organizations.setIamPolicy"]
    ) == []


@pytest.mark.parametrize(
    "scope",
    [
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/gmail.metadata",
        "https://www.googleapis.com/auth/spreadsheets.readonly",
    ],
)
def test_workspace_scope_detection_covers_non_mail_apis(scope):
    assert bare_peass()._is_workspace_scope(scope)


def test_cloud_and_identity_only_scopes_are_not_mislabeled_as_workspace_data():
    peass = bare_peass()
    assert not peass._is_workspace_scope(
        "https://www.googleapis.com/auth/cloud-platform"
    )
    assert not peass._is_workspace_scope(
        "https://www.googleapis.com/auth/userinfo.email"
    )


def test_invalid_permission_bisection_preserves_valid_results():
    peass = bare_peass()
    peass._invalid_permissions = {}
    target = peass.normalize_resource("projects/demo-project")

    def request(method, url, params=None, json=None):
        permissions = json["permissions"]
        if "invalid.permission" in permissions:
            raise GCPApiError(
                400,
                "invalid.permission is not a valid Google Cloud Storage permission.",
                url,
            )
        return {"permissions": [p for p in permissions if p == "resourcemanager.projects.get"]}

    peass.client = SimpleNamespace(request=request)
    found = peass.check_permissions(
        target,
        ["resourcemanager.projects.get", "invalid.permission", "resourcemanager.projects.delete"],
    )
    assert found == ["resourcemanager.projects.get"]
    assert peass._invalid_permissions[target["id"]] == {"invalid.permission"}


def test_invalid_resource_400_is_not_recursively_bisected():
    peass = bare_peass()
    target = peass.normalize_resource("projects/demo-project")
    calls = []

    def request(method, url, params=None, json=None):
        calls.append(list(json["permissions"]))
        raise GCPApiError(400, "Invalid resource name", url, "INVALID_ARGUMENT")

    peass.client = SimpleNamespace(request=request)
    found, complete = peass._check_permissions_with_status(
        target, ["one.permission", "two.permission"]
    )
    assert found == []
    assert complete is False
    assert calls == [["one.permission", "two.permission"]]
    assert len(peass._failures["demo-project"]) == 1


def test_effective_test_does_not_union_denied_static_policy_grant():
    peass = bare_peass()
    peass.num_threads = 1
    peass.get_iam_policy = Mock(
        return_value={
            "bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}]
        }
    )
    peass._query_testable_permissions = Mock(return_value=["resourcemanager.projects.get"])
    peass.client = SimpleNamespace(request=lambda *args, **kwargs: {"permissions": []})
    resource = peass._enumerate_target(peass.normalize_resource("projects/demo-project"))
    assert resource.permissions == []
    assert resource.extra_fields["evidence"] == "testIamPermissions"


def test_policy_is_clearly_labeled_when_effective_test_is_unavailable():
    peass = bare_peass()
    peass.num_threads = 1
    peass.get_iam_policy = Mock(
        return_value={
            "bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}]
        }
    )
    peass._query_testable_permissions = Mock(return_value=["resourcemanager.projects.get"])

    def denied(*args, **kwargs):
        raise GCPApiError(403, "Permission denied", "https://example.googleapis.com")

    peass.client = SimpleNamespace(request=denied)
    resource = peass._enumerate_target(peass.normalize_resource("projects/demo-project"))
    assert resource.permissions == ["resourcemanager.projects.get"]
    assert resource.extra_fields["evidence"] == "IAM policy fallback (unverified)"
    assert "IAM Deny" in resource.extra_fields["enumeration_note"]


def test_shared_analysis_preserves_gcp_evidence_and_caveats():
    peass = bare_peass()
    peass.very_sensitive_combos = []
    peass.sensitive_combos = []
    peass.cloud_provider = "GCP"
    peass.principal_info = {}
    resource = CloudResource(
        "projects/demo-project",
        "demo-project",
        "project",
        ["resourcemanager.projects.get"],
        evidence="IAM policy fallback (unverified)",
        discovery_source="explicit",
        enumeration_note="Effective permission testing was unavailable.",
    )
    grouped = peass.group_resources_by_permissions([resource])
    permissions, resources = next(iter(grouped.items()))
    result = peass.analyze_group(permissions, resources)
    details = result["resource_details"][0]
    assert details["evidence"] == "IAM policy fallback (unverified)"
    assert details["discovery_source"] == "explicit"
    assert details["enumeration_note"] == "Effective permission testing was unavailable."


def test_function_deduplication_prefers_explicit_then_v2():
    peass = bare_peass()
    base = "projects/demo-project/locations/us-central1/functions/fn"
    v1 = peass.normalize_resource(f"function-v1:{base}", source="Functions v1 list")
    v2 = peass.normalize_resource(f"function-v2:{base}", source="Functions v2 list")
    assert peass._deduplicate_targets([v1, v2])[0]["api_version"] == "v2"
    explicit_v1 = peass.normalize_resource(f"function-v1:{base}", source="explicit")
    assert peass._deduplicate_targets([v2, explicit_v1])[0]["api_version"] == "v1"


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


def test_bigquery_child_lists_are_independent_and_normalized():
    peass = bare_peass()

    def paged(url, key, params=None):
        if url.endswith("/tables"):
            return [
                {
                    "tableReference": {
                        "projectId": "demo-project",
                        "datasetId": "data",
                        "tableId": "customers",
                    }
                }
            ]
        raise GCPApiError(403, "Routines denied", url)

    peass._paged_items = paged
    targets = peass._discover_bigquery_children("demo-project", "data")
    assert [target["type"] for target in targets] == ["bigquery_table"]
    assert targets[0]["id"].endswith("/tables/customers")
    assert peass._failures["demo-project"][0][0] == "BigQuery routines list"


def test_kms_fallback_keeps_accessible_locations_after_a_denial():
    peass = bare_peass()

    def paged(url, key, params=None):
        if url.endswith("/locations"):
            return [{"name": "projects/demo-project/locations/denied"}, {"name": "projects/demo-project/locations/global"}]
        if "/locations/denied/keyRings" in url:
            raise GCPApiError(403, "Denied", url)
        if url.endswith("/locations/global/keyRings"):
            return [{"name": "projects/demo-project/locations/global/keyRings/main"}]
        if url.endswith("/keyRings/main/cryptoKeys"):
            return [{"name": "projects/demo-project/locations/global/keyRings/main/cryptoKeys/key"}]
        return []

    peass._paged_items = paged
    targets = peass._discover_kms("demo-project")
    assert [target["type"] for target in targets] == ["kms_keyring", "kms_key"]


def test_secret_discovery_keeps_regional_results_when_global_is_denied():
    peass = bare_peass()

    def paged(url, key, params=None):
        if url.endswith("/projects/demo-project/secrets"):
            raise GCPApiError(403, "Global list denied", url)
        if url.endswith("/projects/demo-project/locations"):
            return [
                {"name": "projects/demo-project/locations/global"},
                {"name": "projects/demo-project/locations/europe-west1"},
            ]
        if url.endswith("/locations/europe-west1/secrets"):
            return [
                {"name": "projects/demo-project/locations/europe-west1/secrets/regional"}
            ]
        return []

    peass._paged_items = paged
    targets = peass._discover_secrets("demo-project")
    assert [target["id"] for target in targets] == [
        "projects/demo-project/locations/europe-west1/secrets/regional"
    ]
    assert peass._failures["demo-project"][0][0] == "Secret Manager in some locations"


def test_regional_secret_iam_calls_use_the_regional_endpoint():
    peass = bare_peass()
    target = peass.normalize_resource(
        "projects/demo-project/locations/europe-west1/secrets/regional"
    )
    _, policy_url, _, _ = peass._policy_request(target)
    _, test_url, _, _ = peass._test_request(target, ["secretmanager.versions.access"])
    expected_host = "https://secretmanager.europe-west1.rep.googleapis.com/v1/"
    assert policy_url.startswith(expected_host)
    assert test_url.startswith(expected_host)
