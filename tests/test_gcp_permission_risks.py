import fnmatch
from pathlib import Path

import pytest
import yaml

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.CloudPEASS.permission_risk_classifier import classify_all, classify_permission
from src.sensitive_permissions.gcp import (
    risk_documentation,
    sensitive_combinations,
    very_sensitive_combinations,
)


@pytest.mark.parametrize(
    "permission",
    [
        "resourcemanager.projects.setIamPolicy",
        "container.pods.exec",
        "container.nodes.proxy",
        "container.serviceAccounts.createToken",
        "cloudbuild.builds.create",
        "composer.environments.executeAirflowCommand",
        "secretmanager.versions.access",
    ],
)
def test_direct_compromise_permissions_are_critical(permission):
    assert classify_permission("gcp", permission) == "critical"


@pytest.mark.parametrize(
    "permission",
    [
        "bigquery.tables.getData",
        "storage.objects.get",
        "artifactregistry.repositories.downloadArtifacts",
        "pubsub.subscriptions.consume",
        "run.routes.invoke",
        "secretmanager.versions.add",
        "secretmanager.versions.destroy",
        "container.clusters.getCredentials",
        "container.pods.attach",
        "container.pods.getLogs",
        "container.pods.proxy",
        "container.services.proxy",
        "bigtable.tables.mutateRows",
        "compute.instances.getSerialPortOutput",
        "healthcare.dicomStores.dicomWebDelete",
        "healthcare.dicomStores.dicomWebRead",
        "healthcare.dicomStores.dicomWebWrite",
        "healthcare.fhirResources.create",
        "healthcare.fhirResources.delete",
        "healthcare.fhirResources.get",
        "healthcare.fhirResources.patch",
        "healthcare.fhirResources.update",
        "healthcare.fhirStores.searchResources",
        "healthcare.hl7V2Messages.get",
        "iam.serviceAccounts.getOpenIdToken",
        "cloudkms.cryptoKeyVersions.destroy",
        "artifactregistry.repositories.uploadArtifacts",
        "datastore.entities.create",
        "datastore.entities.delete",
        "datastore.entities.get",
        "datastore.entities.update",
        "redis.instances.getAuthString",
        "source.repos.update",
        "workflows.executions.create",
    ],
)
def test_data_plane_and_context_dependent_permissions_are_high(permission):
    assert classify_permission("gcp", permission) == "high"


@pytest.mark.parametrize(
    "permission",
    [
        "compute.disks.create",
        "compute.disks.update",
        "monitoring.dashboards.update",
        "cloudasset.assets.exportIamServiceAccountKeys",
        "artifactregistry.files.download",
        "alloydb.instances.executeSql",
        "developerconnect.users.fetchAccessToken",
        "run.services.sshRoot",
        "cloudfunctions.functions.sourceCodeSet",
        "composer.environments.create",
        "container.serviceAccounts.create",
        "monitoring.dashboards.delete",
        "run.jobs.run",
        "run.jobs.runWithOverrides",
        "secretmanager.secrets.update",
        "storage.objects.update",
        "iam.roles.create",
        "logging.views.access",
        "spanner.databases.read",
        "spanner.databases.select",
        "spanner.databases.write",
        "spanner.sessions.create",
        "future.widgets.frobnicate",
    ],
)
def test_operational_or_unknown_permissions_are_medium(permission):
    assert classify_permission("gcp", permission, unknown_default="medium") == "medium"


@pytest.mark.parametrize(
    "permission",
    [
        "iam.serviceAccountKeys.get",
        "iam.serviceAccountKeys.list",
        "secretmanager.secrets.get",
        "secretmanager.versions.list",
        "compute.instances.get",
        "resourcemanager.projects.list",
    ],
)
def test_metadata_reads_are_low(permission):
    assert classify_permission("gcp", permission) == "low"


def test_every_permission_is_assigned_to_exactly_one_category():
    permissions = {
        "iam.serviceAccounts.actAs",
        "storage.objects.get",
        "compute.disks.create",
        "compute.disks.get",
        "unknown.permission.action",
    }
    categories = classify_all("gcp", permissions, unknown_default="medium")
    flattened = [permission for values in categories.values() for permission in values]
    assert set(flattened) == permissions
    assert len(flattened) == len(permissions)


def test_legacy_combinations_do_not_promote_every_create_and_update():
    patterns = {
        pattern
        for combination in very_sensitive_combinations + sensitive_combinations
        for pattern in combination
    }
    assert "*.create" not in patterns
    assert "*.update" not in patterns

    peass = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "GCP",
        1,
    )
    result = peass.analyze_sensitive_combinations(
        {"compute.disks.create", "monitoring.dashboards.update"}
    )
    assert result == {"very_sensitive_perms": set(), "sensitive_perms": set()}


@pytest.mark.parametrize(
    ("incomplete", "complete"),
    [
        (
            {"cloudfunctions.functions.sourceCodeSet"},
            {
                "cloudfunctions.functions.create",
                "cloudfunctions.functions.sourceCodeSet",
                "iam.serviceAccounts.actAs",
            },
        ),
        (
            {"composer.environments.create"},
            {"composer.environments.create", "iam.serviceAccounts.actAs"},
        ),
        (
            {"run.jobs.runWithOverrides"},
            {"run.jobs.run", "run.jobs.runWithOverrides"},
        ),
        (
            {"iam.serviceAccounts.implicitDelegation"},
            {
                "iam.serviceAccounts.implicitDelegation",
                "iam.serviceAccounts.getAccessToken",
            },
        ),
    ],
)
def test_context_dependent_privesc_is_critical_only_when_complete(incomplete, complete):
    peass = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "GCP",
        1,
    )
    incomplete_result = peass.analyze_sensitive_combinations(incomplete)
    assert incomplete_result["very_sensitive_perms"] == set()

    complete_result = peass.analyze_sensitive_combinations(complete)
    assert complete_result["very_sensitive_perms"] == complete


def test_only_updating_an_existing_custom_role_is_directly_critical():
    assert classify_permission("gcp", "iam.roles.create") == "medium"
    assert classify_permission("gcp", "iam.roles.update") == "critical"


def test_preknown_gke_endpoint_does_not_require_cluster_discovery_permission():
    peass = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "GCP",
        1,
    )
    permission = "container.serviceAccounts.createToken"
    result = peass.analyze_sensitive_combinations({permission})
    assert result["very_sensitive_perms"] == {permission}


def test_cloud_sql_data_api_is_high_only_with_login_permission():
    peass = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "GCP",
        1,
    )
    execute_only = peass.analyze_sensitive_combinations(
        {"cloudsql.instances.executeSql"}
    )
    assert execute_only["sensitive_perms"] == set()

    complete = {"cloudsql.instances.executeSql", "cloudsql.instances.login"}
    result = peass.analyze_sensitive_combinations(complete)
    assert result["sensitive_perms"] == complete


def test_logging_data_access_is_high_only_with_list_and_view_permissions():
    peass = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "GCP",
        1,
    )
    for incomplete in (
        {"logging.logEntries.list"},
        {"logging.views.access"},
    ):
        result = peass.analyze_sensitive_combinations(incomplete)
        assert result["sensitive_perms"] == set()

    complete = {"logging.logEntries.list", "logging.views.access"}
    result = peass.analyze_sensitive_combinations(complete)
    assert result["sensitive_perms"] == complete


@pytest.mark.parametrize(
    "data_permission",
    [
        "spanner.databases.read",
        "spanner.databases.select",
        "spanner.databases.write",
    ],
)
def test_spanner_data_access_is_high_only_with_session_creation(data_permission):
    peass = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "GCP",
        1,
    )
    for incomplete in (
        {data_permission},
        {"spanner.sessions.create"},
    ):
        result = peass.analyze_sensitive_combinations(incomplete)
        assert result["sensitive_perms"] == set()

    complete = {data_permission, "spanner.sessions.create"}
    result = peass.analyze_sensitive_combinations(complete)
    assert result["sensitive_perms"] == complete


def test_bundled_exact_risk_rules_do_not_overlap():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "CloudPEASS"
        / "risk_rules"
        / "gcp.yaml"
    )
    rules = yaml.safe_load(path.read_text(encoding="utf-8"))
    exact_sets = {
        level: set(rules.get(f"{level}_exact") or [])
        for level in ("critical", "high", "medium", "low")
    }
    for level, permissions in exact_sets.items():
        others = set().union(
            *(values for other, values in exact_sets.items() if other != level)
        )
        assert not permissions & others, level


def test_every_high_or_critical_rule_has_hacktricks_evidence():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "CloudPEASS"
        / "risk_rules"
        / "gcp.yaml"
    )
    rules = yaml.safe_load(path.read_text(encoding="utf-8"))
    exact_permissions = set(rules.get("critical_exact") or []) | set(
        rules.get("high_exact") or []
    )
    combination_permissions = {
        permission
        for combination in very_sensitive_combinations + sensitive_combinations
        for permission in combination
    }
    for permission in exact_permissions | combination_permissions:
        assert any(
            fnmatch.fnmatchcase(permission, pattern)
            for pattern, _ in risk_documentation
        ), permission

    for _, document in risk_documentation:
        assert document.startswith(("gcp-privilege-escalation/", "gcp-post-exploitation/"))
        assert document.endswith(".md")
