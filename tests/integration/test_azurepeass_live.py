"""Opt-in Azure integration test with disposable RBAC fixtures.

Run only against a dedicated test subscription::

    CLOUDPEASS_AZURE_LIVE_TEST=1 \
    CLOUDPEASS_AZURE_TEST_SUBSCRIPTION=<uuid> \
    PYTHONPATH=src pytest -q -s tests/integration/test_azurepeass_live.py

The test never prints application credentials and removes every created Azure and
Entra object in a ``finally`` block.  Normal test runs skip this module.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import jwt
import msal
import pytest

from azure.arm import AzureARMEnumerator


LIVE = os.getenv("CLOUDPEASS_AZURE_LIVE_TEST") == "1"
SUBSCRIPTION = os.getenv("CLOUDPEASS_AZURE_TEST_SUBSCRIPTION", "")

pytestmark = pytest.mark.skipif(
    not LIVE,
    reason="set CLOUDPEASS_AZURE_LIVE_TEST=1 to create disposable Azure fixtures",
)


def _az(*args, check=True):
    env = os.environ.copy()
    env.update(
        {
            "AZURE_CORE_COLLECT_TELEMETRY": "no",
            "AZURE_CORE_DISABLE_CONFIRM_PROMPT": "yes",
            "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
        }
    )
    result = subprocess.run(
        ["az", *args, "--only-show-errors"],
        text=True,
        capture_output=True,
        timeout=180,
        env=env,
        check=False,
    )
    if check and result.returncode:
        raise AssertionError(
            f"az {' '.join(args[:3])} failed ({result.returncode}): "
            f"{result.stderr[-1000:]}"
        )
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip()


def _eventually(callback, predicate, *, timeout=150, interval=8):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = callback()
        if predicate(last):
            return last
        time.sleep(interval)
    raise AssertionError(f"Azure state did not converge before timeout; last={last!r}")


def _client_token(tenant_id, app_id, secret, resource):
    # Hide this helper's arguments from pytest tracebacks: one of them is a
    # short-lived client secret used only by this disposable fixture.
    __tracebackhide__ = True
    deadline = time.monotonic() + 120
    last_codes = []
    while time.monotonic() < deadline:
        app = msal.ConfidentialClientApplication(
            app_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=secret,
        )
        result = app.acquire_token_for_client(scopes=[f"{resource}/.default"])
        if "access_token" in result:
            return result["access_token"]
        last_codes = result.get("error_codes") or [result.get("error", "unknown")]
        if not ({700016, 7000215} & set(last_codes)):
            break
        time.sleep(6)
    raise AssertionError(
        f"disposable application credential was not usable; error codes: {last_codes}"
    )


def _create_application(prefix):
    app = _az("ad", "app", "create", "--display-name", prefix, "--output", "json")
    app_id = app["appId"]
    service_principal = _az("ad", "sp", "create", "--id", app_id, "--output", "json")
    credential = _az(
        "ad",
        "app",
        "credential",
        "reset",
        "--id",
        app_id,
        "--append",
        "--years",
        "1",
        "--output",
        "json",
    )
    return {
        "app_id": app_id,
        "object_id": service_principal["id"],
        "secret": credential["password"],
    }


def _delete_if_present(*args):
    return _az(*args, check=False)


def test_azure_permission_edge_cases_and_cleanup():
    assert SUBSCRIPTION, "CLOUDPEASS_AZURE_TEST_SUBSCRIPTION is required"
    account = _az("account", "show", "--subscription", SUBSCRIPTION, "--output", "json")
    assert account["id"].lower() == SUBSCRIPTION.lower()
    tenant_id = account["tenantId"]

    suffix = uuid.uuid4().hex[:10]
    prefix = f"cloudpeass-live-{suffix}"
    location = os.getenv("CLOUDPEASS_AZURE_TEST_LOCATION", "westeurope")
    resource_group = prefix
    storage_name = f"cplive{suffix}"[:24]
    group_name = f"{prefix}-group"
    custom_role_name = f"CloudPEASS live {suffix}"
    custom_role_id = str(uuid.uuid4())
    subscription_scope = f"/subscriptions/{SUBSCRIPTION}"
    rg_scope = f"{subscription_scope}/resourceGroups/{resource_group}"
    storage_scope = (
        f"{rg_scope}/providers/Microsoft.Storage/storageAccounts/{storage_name}"
    )

    applications = []
    group_id = None
    role_assignment_ids = []
    conditional_created = False
    role_definition_created = False
    rbac_fixture_supported = False
    try:
        _az(
            "group",
            "create",
            "--subscription",
            SUBSCRIPTION,
            "--name",
            resource_group,
            "--location",
            location,
            "--output",
            "json",
        )
        _az(
            "storage",
            "account",
            "create",
            "--subscription",
            SUBSCRIPTION,
            "--resource-group",
            resource_group,
            "--name",
            storage_name,
            "--location",
            location,
            "--sku",
            "Standard_LRS",
            "--allow-blob-public-access",
            "false",
            "--output",
            "json",
        )

        custom_role = {
            "Name": custom_role_name,
            "Id": custom_role_id,
            "IsCustom": True,
            "Description": "Disposable CloudPEASS integration-test role",
            "Actions": ["Microsoft.Storage/*"],
            "NotActions": ["Microsoft.Storage/storageAccounts/listKeys/action"],
            "DataActions": [
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
            ],
            "NotDataActions": [
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
            ],
            "AssignableScopes": [subscription_scope],
        }
        created_role = _az(
            "role",
            "definition",
            "create",
            "--subscription",
            SUBSCRIPTION,
            "--role-definition",
            json.dumps(custom_role),
            "--output",
            "json",
            check=False,
        )
        role_definition_created = isinstance(created_role, dict) and bool(created_role)
        if not role_definition_created:
            print(
                "Azure RBAC fixture creation is unavailable to this operator; "
                "continuing with discovery and zero-role principal cases."
            )

        # Application creation is intentionally independent of Azure RBAC.  It
        # provides a real no-subscription-access token even when the operator is
        # only Contributor and cannot create role definitions/assignments.
        no_access = _create_application(f"{prefix}-none")
        applications.append(no_access)

        current_token_data = _az(
            "account",
            "get-access-token",
            "--subscription",
            SUBSCRIPTION,
            "--resource",
            "https://management.azure.com/",
            "--output",
            "json",
        )
        current_arm = AzureARMEnumerator(current_token_data["accessToken"])
        resource_groups, rg_status, _ = current_arm.list_resource_groups(SUBSCRIPTION)
        resources, resources_status, _ = current_arm.list_resources(SUBSCRIPTION)
        assert rg_status == 200 and any(item.get("id", "").lower() == rg_scope.lower() for item in resource_groups)
        assert resources_status == 200 and any(item.get("id", "").lower() == storage_scope.lower() for item in resources)

        if role_definition_created:
            direct = _create_application(f"{prefix}-direct")
            transitive = _create_application(f"{prefix}-group-member")
            applications.extend((direct, transitive))

            group = _az(
                "ad",
                "group",
                "create",
                "--display-name",
                group_name,
                "--mail-nickname",
                f"cplive{suffix}",
                "--output",
                "json",
            )
            group_id = group["id"]
            _az(
                "ad",
                "group",
                "member",
                "add",
                "--group",
                group_id,
                "--member-id",
                transitive["object_id"],
            )

            first_assignment = _az(
                "role",
                "assignment",
                "create",
                "--subscription",
                SUBSCRIPTION,
                "--assignee-object-id",
                direct["object_id"],
                "--assignee-principal-type",
                "ServicePrincipal",
                "--role",
                "Reader",
                "--scope",
                rg_scope,
                "--output",
                "json",
                check=False,
            )
            rbac_fixture_supported = isinstance(first_assignment, dict) and bool(
                first_assignment.get("id")
            )
            if rbac_fixture_supported:
                role_assignment_ids.append(first_assignment["id"])
                for assignee, principal_type, role, scope in (
                    (group_id, "Group", "Reader", rg_scope),
                    (direct["object_id"], "ServicePrincipal", custom_role_id, storage_scope),
                ):
                    assignment = _az(
                        "role",
                        "assignment",
                        "create",
                        "--subscription",
                        SUBSCRIPTION,
                        "--assignee-object-id",
                        assignee,
                        "--assignee-principal-type",
                        principal_type,
                        "--role",
                        role,
                        "--scope",
                        scope,
                        "--output",
                        "json",
                    )
                    role_assignment_ids.append(assignment["id"])

                conditional = _az(
                    "role",
                    "assignment",
                    "create",
                    "--subscription",
                    SUBSCRIPTION,
                    "--assignee-object-id",
                    direct["object_id"],
                    "--assignee-principal-type",
                    "ServicePrincipal",
                    "--role",
                    "Storage Blob Data Reader",
                    "--scope",
                    storage_scope,
                    "--condition-version",
                    "2.0",
                    "--condition",
                    "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEqualsIgnoreCase 'cloudpeass-allowed'",
                    "--output",
                    "json",
                    check=False,
                )
                if isinstance(conditional, dict) and conditional.get("id"):
                    conditional_created = True
                    role_assignment_ids.append(conditional["id"])
                else:
                    print(
                        "Conditional RBAC fixture is unavailable; deterministic "
                        "condition parsing tests still cover this branch."
                    )

        no_access_token = _client_token(
            tenant_id, no_access["app_id"], no_access["secret"], "https://management.azure.com"
        )
        assert jwt.decode(no_access_token, options={"verify_signature": False})["oid"] == no_access["object_id"]

        no_access_arm = AzureARMEnumerator(no_access_token)
        denied = no_access_arm.get_effective_permissions(rg_scope)
        assert not denied.allowed
        assert denied.status_code in {200, 401, 403, 404}

        if rbac_fixture_supported:
            direct_token = _client_token(
                tenant_id,
                direct["app_id"],
                direct["secret"],
                "https://management.azure.com",
            )
            transitive_token = _client_token(
                tenant_id,
                transitive["app_id"],
                transitive["secret"],
                "https://management.azure.com",
            )
            direct_arm = AzureARMEnumerator(direct_token)
            direct_permissions = _eventually(
                lambda: direct_arm.get_effective_permissions(rg_scope),
                lambda result: result.succeeded
                and any("read" in item.lower() for item in result.allowed),
            )
            assert direct_permissions.succeeded

            storage_permissions = _eventually(
                lambda: direct_arm.get_effective_permissions(storage_scope),
                lambda result: (
                    result.succeeded
                    and "Microsoft.Storage/storageAccounts/listKeys/action"
                    in result.excluded
                    and any("blobs/read" in item for item in result.allowed)
                ),
            )
            assert (
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
                in storage_permissions.excluded
            )

            direct_assignments = _eventually(
                lambda: direct_arm.list_assignments_for_principal(
                    storage_scope, direct["object_id"]
                ),
                lambda result: result[1] == 200
                and len(result[0]) >= (3 if conditional_created else 2),
            )[0]
            if conditional_created:
                assert any(
                    item.get("properties", {}).get("condition")
                    for item in direct_assignments
                )

            transitive_arm = AzureARMEnumerator(transitive_token)
            transitive_permissions = _eventually(
                lambda: transitive_arm.get_effective_permissions(rg_scope),
                lambda result: result.succeeded
                and any("read" in item.lower() for item in result.allowed),
            )
            assert transitive_permissions.succeeded
            inherited = _eventually(
                lambda: transitive_arm.list_assignments_for_principal(
                    rg_scope, transitive["object_id"]
                ),
                lambda result: result[1] == 200 and bool(result[0]),
            )[0]
            assert any(
                item.get("properties", {}).get("principalId") == group_id
                for item in inherited
            )

        # Graph client-credential tokens contain claims even when the application
        # has no directory read grants, exercising the scanner's zero-permission fallback.
        graph_token = _client_token(
            tenant_id, no_access["app_id"], no_access["secret"], "https://graph.microsoft.com"
        )
        graph_claims = jwt.decode(graph_token, options={"verify_signature": False})
        assert graph_claims["oid"] == no_access["object_id"]
        assert graph_claims.get("idtyp") == "app"

        scanner_env = os.environ.copy()
        scanner_env.update(
            {
                "AZURE_ARM_TOKEN": no_access_token,
                "AZURE_GRAPH_TOKEN": graph_token,
                "PYTHONPATH": "src",
            }
        )
        scanner = subprocess.run(
            [
                sys.executable,
                "AzurePEAS.py",
                "--tenant-id",
                tenant_id,
                "--check-only-these-subs",
                SUBSCRIPTION,
                "--scopes",
                f"{rg_scope},{storage_scope}",
                "--not-enumerate-m365",
                "--skip-az-cli-fallback",
                "--no-ask",
                "--threads",
                "2",
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=scanner_env,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        assert scanner.returncode == 0, scanner.stderr[-2000:]
        assert no_access["object_id"] in scanner.stdout
        assert "Principal Type (ARM Token): application/managed identity" in scanner.stdout
    finally:
        for assignment_id in reversed(role_assignment_ids):
            _delete_if_present(
                "role",
                "assignment",
                "delete",
                "--subscription",
                SUBSCRIPTION,
                "--ids",
                assignment_id,
            )
        _delete_if_present(
            "group",
            "delete",
            "--subscription",
            SUBSCRIPTION,
            "--name",
            resource_group,
            "--yes",
            "--no-wait",
        )
        _delete_if_present(
            "group",
            "wait",
            "--subscription",
            SUBSCRIPTION,
            "--name",
            resource_group,
            "--deleted",
            "--timeout",
            "300",
        )
        if role_definition_created:
            _delete_if_present(
                "role",
                "definition",
                "delete",
                "--subscription",
                SUBSCRIPTION,
                "--name",
                custom_role_id,
            )
        if group_id:
            _delete_if_present("ad", "group", "delete", "--group", group_id)
        for application in reversed(applications):
            _delete_if_present("ad", "app", "delete", "--id", application["app_id"])

        assert not _az(
            "group",
            "exists",
            "--subscription",
            SUBSCRIPTION,
            "--name",
            resource_group,
            "--output",
            "tsv",
            check=False,
        )
        remaining_role = _az(
            "role",
            "definition",
            "list",
            "--subscription",
            SUBSCRIPTION,
            "--name",
            custom_role_id,
            "--output",
            "json",
            check=False,
        )
        assert not remaining_role
        if group_id:
            assert not _az(
                "ad", "group", "show", "--group", group_id, "--output", "json", check=False
            )
        for application in applications:
            assert not _az(
                "ad",
                "app",
                "show",
                "--id",
                application["app_id"],
                "--output",
                "json",
                check=False,
            )
            assert not _az(
                "ad",
                "sp",
                "show",
                "--id",
                application["app_id"],
                "--output",
                "json",
                check=False,
            )
