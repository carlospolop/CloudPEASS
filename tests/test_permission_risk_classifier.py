import re
import unittest
from pathlib import Path
from typing import Optional

import CloudPEASS.permission_risk_classifier as risk_classifier
from CloudPEASS.cloudpeass import CloudPEASS, CloudResource
from CloudPEASS.permission_risk_classifier import (
    AzureRules,
    azure_regex_classify,
    classify_all,
    classify_permission,
)
from sensitive_permissions.aws import (
    sensitive_combinations,
    tested_risk_documentation,
    very_sensitive_combinations,
)


def azure_rules() -> AzureRules:
    dangerous_write_keywords = (
        "microsoft.authorization/",
        "roleassignments",
        "roledefinitions",
        "elevateaccess",
        "authorization",
        "managedidentity",
        "microsoft.keyvault/",
        "/secrets/",
        "/keys/",
        "/certificates/",
        "policy",
        "privatelink",
        "privateendpoint",
    )
    return AzureRules(
        credential_action_re=re.compile(
            r"/(listsecrets|listkeys|listcredentials|listcredential|listadminkeys|listadminkey|getsecret|getsecrets|getkeys|getkey|getadminkeys|getadminkey|getauthtoken|getaccesstoken|regeneratekey|regeneratekeys|regeneratepassword|generatecredentials|generatecredential|generatekey|generatetoken|listpasswords|listpassword)/action$",
            re.IGNORECASE,
        ),
        storage_insights_child_re=re.compile(
            r"^microsoft\.storage/storageaccounts/(blobservices|fileservices|queueservices|tableservices)/providers/microsoft\.insights/(diagnosticsettings|logdefinitions|metricdefinitions)/read$",
            re.IGNORECASE,
        ),
        register_like_action_re=re.compile(r"/(register|unregister|checknameavailability)/action$", re.IGNORECASE),
        provider_diagnostic_settings_write_re=re.compile(
            r"/providers/microsoft\.insights/diagnosticsettings/write$",
            re.IGNORECASE,
        ),
        boundary_keywords=(
            "networksecurityperimeter",
            "privatelink",
            "privateendpoint",
            "scopedprivatelink",
            "privateendpointconnection",
        ),
        cost_mgmt_exact_medium={
            "microsoft.costmanagement/query/action",
            "microsoft.costmanagement/forecast/action",
            "microsoft.costmanagement/calculatecost/action",
            "microsoft.costmanagement/fetchprices/action",
            "microsoft.advisor/generaterecommendations/action",
            "microsoft.consumption/budgets/write",
        },
        insights_exclude_keywords=("/apikeys/", "apikey", "secret", "token", "credential", "key"),
        insights_medium_prefixes_write=(
            "microsoft.insights/diagnosticsettings/",
            "microsoft.insights/extendeddiagnosticsettings/",
            "microsoft.insights/actiongroups/",
            "microsoft.insights/metricalerts/",
            "microsoft.insights/logprofiles/",
            "microsoft.insights/workbooks/",
            "microsoft.insights/workbooktemplates/",
            "microsoft.insights/webtests/",
        ),
        insights_medium_prefixes_write_or_action=(
            "microsoft.insights/autoscalesettings/",
            "microsoft.insights/metrics/",
            "microsoft.insights/scheduledqueryrules/",
        ),
        insights_activitylogalerts_prefix="microsoft.insights/activitylogalerts/",
        insights_alertrules_prefix="microsoft.insights/alertrules/",
        medium_write_action_provider_prefixes=(
            "microsoft.support/",
            "microsoft.advisor/",
            "microsoft.costmanagement/",
        ),
        resourcehealth_events_action_prefix="microsoft.resourcehealth/events/",
        billing_provider_prefix="microsoft.billing/",
        billing_exclude_keywords=(
            "billingroleassignments",
            "createbillingroleassignment",
            "resolvebillingroleassignments",
            "/elevate/action",
            "roleassignments",
            "roledefinitions",
            "authorization",
        ),
        appinsights_component_prefix="microsoft.insights/components/",
        appinsights_exclude_keywords=("/apikeys/", "apikey", "exportconfiguration", "linkedstorageaccounts"),
        dangerous_write_keywords=dangerous_write_keywords,
        dangerous_write_keywords_lower=tuple(k.lower() for k in dangerous_write_keywords),
    )


class AzureWildcardClassificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = azure_rules()

    def classify(self, permission: str) -> Optional[str]:
        return azure_regex_classify(permission, self.rules)

    def test_global_and_provider_root_wildcards_stay_critical(self) -> None:
        self.assertEqual(self.classify("*"), "critical")
        self.assertEqual(self.classify("*/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Authorization/*"), "critical")
        self.assertEqual(self.classify("Microsoft.KeyVault/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Storage/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Support/*"), "medium")
        self.assertEqual(self.classify("Microsoft.CostManagement/*"), "medium")
        self.assertEqual(self.classify("Microsoft.Maintenance/*"), "medium")
        self.assertEqual(self.classify("Microsoft.Kubernetes/*"), "high")

    def test_resource_type_wildcards_are_not_automatically_critical(self) -> None:
        self.assertEqual(self.classify("Microsoft.HybridCompute/licenses/*"), "medium")
        self.assertEqual(self.classify("Microsoft.Insights/actionGroups/*"), "medium")
        self.assertEqual(self.classify("Microsoft.Compute/virtualMachines/*"), "critical")

    def test_wildcards_keep_maximum_risk_from_likely_child_verbs(self) -> None:
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/secrets/read"), "low")
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/secrets/write"), "high")
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/secrets/*"), "critical")
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/certificates/*"), "high")
        self.assertEqual(
            self.classify(
                "Microsoft.ManagedIdentity/userAssignedIdentities/associatedResources/*"
            ),
            "medium",
        )
        self.assertEqual(
            self.classify("Microsoft.Storage/storageAccounts/blobServices/*"),
            "high",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.ContainerService/managedClusters/rbac.authorization.k8s.io/*"
            ),
            "high",
        )

    def test_known_privilege_escalation_wildcards_stay_critical(self) -> None:
        self.assertEqual(self.classify("Microsoft.Authorization/roleAssignments/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Authorization/roleDefinitions/*"), "high")
        self.assertEqual(self.classify("Microsoft.ManagedIdentity/userAssignedIdentities/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Storage/storageAccounts/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Resources/deploymentScripts/*"), "high")

    def test_cross_provider_wildcard_verbs_are_not_treated_as_literal_operations(self) -> None:
        self.assertEqual(self.classify("*/read"), "medium")
        self.assertEqual(self.classify("*/delete"), "medium")
        self.assertEqual(self.classify("*/write"), "critical")
        self.assertEqual(self.classify("*/action"), "critical")
        self.assertEqual(self.classify("Microsoft.Network/*/read"), "medium")
        self.assertEqual(self.classify("Microsoft.Network/*/write"), "high")
        self.assertEqual(self.classify("Microsoft.Network/*/delete"), "medium")
        self.assertEqual(self.classify("Microsoft.Storage/*/read"), "high")

    def test_arm_metadata_operational_and_sensitive_actions_use_distinct_tiers(self) -> None:
        self.assertEqual(self.classify("Microsoft.Network/virtualNetworks/read"), "low")
        self.assertEqual(self.classify("Microsoft.Network/virtualNetworks/write"), "medium")
        self.assertEqual(self.classify("Microsoft.Network/virtualNetworks/delete"), "medium")
        self.assertEqual(
            self.classify("Microsoft.KeyVault/vaults/secrets/readMetadata/action"),
            "medium",
        )
        self.assertEqual(
            self.classify("Microsoft.KeyVault/vaults/secrets/getSecret/action"),
            "critical",
        )
        self.assertEqual(
            self.classify("Microsoft.Search/searchServices/listQueryKeys/action"),
            "high",
        )
        tested_sensitive_data_credentials = {
            "Microsoft.Search/searchServices/createQueryKey/action": "high",
            "Microsoft.Search/searchServices/regenerateAdminKey/action": "critical",
            "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action": "high",
            "Microsoft.DocumentDB/databaseAccounts/readonlykeys/read": "high",
            "Microsoft.Logic/workflows/triggers/listCallbackUrl/action": "high",
            "Microsoft.Logic/workflows/versions/triggers/listCallbackUrl/action": "high",
            "Microsoft.Logic/workflows/triggers/run/action": "high",
            "Microsoft.Logic/workflows/triggers/histories/resubmit/action": "high",
            "Microsoft.DataFactory/factories/pipelines/createRun/action": "high",
            "Microsoft.App/jobs/start/action": "critical",
            "Microsoft.App/jobs/listSecrets/action": "critical",
            "Microsoft.App/managedEnvironments/daprComponents/listSecrets/action": "critical",
            "Microsoft.Devices/provisioningServices/listkeys/action": "critical",
            "Microsoft.Devices/provisioningServices/keys/listkeys/action": "critical",
            "Microsoft.Compute/disks/beginGetAccess/action": "high",
            "Microsoft.Compute/snapshots/beginGetAccess/action": "high",
            "Microsoft.Compute/restorePointCollections/restorePoints/diskRestorePoints/beginGetAccess/action": "high",
        }
        for permission, expected in tested_sensitive_data_credentials.items():
            with self.subTest(permission=permission):
                self.assertEqual(self.classify(permission), expected)
        self.assertEqual(
            self.classify("Microsoft.Compute/virtualMachines/runCommands/write"),
            "critical",
        )
        self.assertEqual(
            self.classify("Microsoft.MachineLearningServices/workspaces/data/write"),
            "high",
        )
        self.assertEqual(
            self.classify("Microsoft.MachineLearningServices/workspaces/data/delete"),
            "medium",
        )
        self.assertEqual(
            self.classify("Microsoft.ManagedIdentity/userAssignedIdentities/write"),
            "medium",
        )
        self.assertEqual(
            self.classify("Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"),
            "high",
        )
        self.assertEqual(
            self.classify("Microsoft.Authorization/roleDefinitions/write"), "high"
        )
        self.assertEqual(
            self.classify("Microsoft.App/containerApps/getAuthToken/action"), "high"
        )
        self.assertEqual(
            self.classify("Microsoft.KeyVault/vaults/certificates/purge/action"),
            "medium",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.ServiceBus/namespaces/authorizationRules/write"
            ),
            "medium",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.AppConfiguration/configurationStores/ListKeys/action"
            ),
            "critical",
        )
        self.assertEqual(
            self.classify("Microsoft.Devices/IotHubs/listkeys/action"),
            "critical",
        )
        self.assertEqual(
            self.classify("Microsoft.Storage/storageAccounts/listAccountSas/action"),
            "critical",
        )
        self.assertEqual(
            self.classify("Microsoft.Storage/storageAccounts/listServiceSas/action"),
            "critical",
        )
        self.assertEqual(
            self.classify("Microsoft.EventGrid/topics/listKeys/action"),
            "high",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.OperationalInsights/workspaces/listKeys/action"
            ),
            "high",
        )
        self.assertEqual(
            self.classify("Microsoft.SignalRService/SignalR/listkeys/action"),
            "high",
        )
        self.assertEqual(
            self.classify("Microsoft.SignalRService/WebPubSub/listkeys/action"),
            "high",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.Communication/CommunicationServices/ListKeys/action"
            ),
            "high",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.Relay/namespaces/HybridConnections/authorizationRules/listkeys/action"
            ),
            "high",
        )
        self.assertEqual(
            self.classify(
                "Microsoft.NotificationHubs/Namespaces/NotificationHubs/authorizationRules/listkeys/action"
            ),
            "critical",
        )
        tested_credential_actions = {
            "Microsoft.SignalRService/SignalR/regeneratekey/action": "high",
            "Microsoft.SignalRService/WebPubSub/regeneratekey/action": "high",
            "Microsoft.Communication/CommunicationServices/RegenerateKey/action": "high",
            "Microsoft.Relay/namespaces/authorizationRules/listkeys/action": "high",
            "Microsoft.Relay/namespaces/authorizationRules/regenerateKeys/action": "high",
            "Microsoft.Relay/namespaces/HybridConnections/authorizationRules/regeneratekeys/action": "high",
            "Microsoft.Relay/namespaces/WcfRelays/authorizationRules/listkeys/action": "high",
            "Microsoft.Relay/namespaces/WcfRelays/authorizationRules/regeneratekeys/action": "high",
            "Microsoft.NotificationHubs/Namespaces/authorizationRules/listkeys/action": "critical",
            "Microsoft.NotificationHubs/Namespaces/authorizationRules/regenerateKeys/action": "critical",
            "Microsoft.NotificationHubs/Namespaces/NotificationHubs/authorizationRules/regenerateKeys/action": "critical",
        }
        for permission, expected in tested_credential_actions.items():
            with self.subTest(permission=permission):
                self.assertEqual(self.classify(permission), expected)

    def test_graph_scopes_and_unresolved_entra_evidence_are_classified(self) -> None:
        self.assertEqual(self.classify("openid"), "low")
        self.assertEqual(self.classify("User.Read"), "low")
        self.assertEqual(self.classify("User.ReadBasic.All"), "medium")
        self.assertEqual(self.classify("Directory.Read.All"), "high")
        self.assertEqual(self.classify("Directory.ReadWrite.All"), "high")
        self.assertEqual(self.classify("Mail.Read"), "high")
        self.assertEqual(self.classify("Application.ReadWrite.All"), "critical")
        self.assertEqual(self.classify("RoleManagement.ReadWrite.Directory"), "critical")
        self.assertEqual(self.classify("Application.Read.All"), "medium")
        self.assertEqual(self.classify("Policy.ReadWrite.ConditionalAccess"), "medium")
        self.assertEqual(self.classify("Printer.ReadWrite.All"), "medium")
        self.assertEqual(self.classify("Sites.FullControl.All"), "high")
        self.assertEqual(self.classify("Microsoft.Teams/settings/update"), "medium")
        self.assertEqual(self.classify("entra.directoryRole/unknown-guid"), "medium")
        self.assertEqual(self.classify("Owner of #microsoft.graph.group"), "high")
        self.assertEqual(
            self.classify("Owner of #microsoft.graph.application"), "critical"
        )

    def test_entra_granular_role_actions_are_not_left_unknown(self) -> None:
        self.assertEqual(
            self.classify("microsoft.directory/domains/allProperties/read"), "low"
        )
        self.assertEqual(
            self.classify("microsoft.directory/domains/allProperties/update"), "medium"
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/domains/federationConfiguration/basic/update"
            ),
            "high",
        )
        self.assertEqual(
            self.classify("microsoft.directory/applications/credentials/update"),
            "critical",
        )
        self.assertEqual(
            self.classify("microsoft.directory/bitlockerKeys/key/read"), "critical"
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/users/authenticationMethods/standard/read"
            ),
            "medium",
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/users/authenticationMethods/basic/update"
            ),
            "critical",
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/groupsAssignableToRoles/allProperties/update"
            ),
            "medium",
        )
        self.assertEqual(
            self.classify("microsoft.directory/groups/allProperties/update"),
            "medium",
        )
        self.assertEqual(
            self.classify("microsoft.directory/users/basic/update"), "medium"
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/groupsAssignableToRoles/assignLicense"
            ),
            "medium",
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/agentIdentityBlueprints/credentials/update"
            ),
            "critical",
        )
        self.assertEqual(
            self.classify(
                "microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-company-admin"
            ),
            "critical",
        )
        self.assertEqual(
            self.classify("microsoft.directory/auditLogs/allProperties/read"),
            "high",
        )
        self.assertEqual(
            self.classify("microsoft.agentRegistry/allEntities/allProperties/allTasks"),
            "high",
        )
        self.assertEqual(
            self.classify("microsoft.networkAccess/trafficLogs/standard/read"),
            "high",
        )

    def test_cli_capability_evidence_has_explicit_risk(self) -> None:
        self.assertEqual(self.classify("az-cli/read/vm/list"), "low")
        self.assertEqual(
            self.classify("az-cli/read/storage/account/list-keys"), "critical"
        )

    def test_catalog_keywords_do_not_promote_metadata_or_lifecycle_operations(self) -> None:
        expected = {
            "Microsoft.Storage/storageAccounts/blobServices/read": "low",
            "Microsoft.Storage/storageAccounts/blobServices/write": "medium",
            "Microsoft.Storage/storageAccounts/blobServices/containers/read": "low",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read": "high",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action": "medium",
            "Microsoft.KeyVault/vaults/secrets/recover/action": "medium",
            "Microsoft.KeyVault/vaults/secrets/setSecret/action": "high",
            "Microsoft.Automation/automationAccounts/certificates/getCount/action": "medium",
            "Microsoft.Devices/iotHubs/certificates/generateVerificationCode/action": "medium",
            "Microsoft.ManagedIdentity/userAssignedIdentities/listAssociatedResources/action": "medium",
        }
        for permission, level in expected.items():
            with self.subTest(permission=permission):
                self.assertEqual(self.classify(permission), level)


class AwsRiskClassificationTest(unittest.TestCase):
    def test_admin_and_privilege_escalation_patterns_are_critical(self) -> None:
        for permission in (
            "*",
            "*:*",
            "iam:*",
            "iam:Create*",
            "iam:create*",
            "sts:Assume*",
            "*:Get*",
        ):
            with self.subTest(permission=permission):
                self.assertEqual(
                    classify_permission("aws", permission, unknown_default="medium"),
                    "critical",
                )

    def test_sensitive_and_discovery_wildcards_use_maximum_implied_risk(self) -> None:
        expected = {
            "s3:Get*": "high",
            "s3:GetObject*": "high",
            "lambda:Invoke*": "high",
            "ec2:Run*": "high",
            "codebuild:Start*": "high",
            "ec2:Describe*": "low",
            "s3:List*": "low",
            "madeup:Unknown*": "high",
        }
        for permission, level in expected.items():
            with self.subTest(permission=permission):
                self.assertEqual(
                    classify_permission("aws", permission, unknown_default="medium"),
                    level,
                )

    def test_exact_benign_and_sensitive_actions_keep_expected_risk(self) -> None:
        expected = {
            "iam:GetUser": "low",
            "iam:CreateUser": "medium",
            "logs:PutLogEvents": "low",
            "amplifybackend:GetToken": "low",
            "cognito-identity:GetOpenIdToken": "low",
            "codeartifact:GetAuthorizationToken": "high",
            "ec2:GetPasswordData": "high",
            "events:RetrieveConnectionCredentials": "medium",
            "sts:GetDelegatedAccessToken": "high",
            "sts:GetServiceBearerToken": "high",
            "appsync:PutResourcePolicy": "high",
            "acm:DescribeCertificate": "low",
            "s3:GetObject": "high",
            "kms:Decrypt": "critical",
            "secretsmanager:GetSecretValue": "critical",
            "ssm:GetParameter": "critical",
            "madeup:UnknownAction": "medium",
        }
        for permission, level in expected.items():
            with self.subTest(permission=permission):
                self.assertEqual(
                    classify_permission("aws", permission, unknown_default="medium"),
                    level,
                )

    def test_live_validated_sensitive_reads_and_credentials_are_high(self) -> None:
        expected = {
            "lambda:GetFunction": "high",
            "route53domains:GetDomainDetail": "high",
            "sts:GetFederationToken": "high",
        }
        self.assertEqual(set(tested_risk_documentation), set(expected))
        for permission, level in expected.items():
            with self.subTest(permission=permission):
                self.assertEqual(
                    classify_permission("aws", permission, unknown_default="medium"),
                    level,
                )
                self.assertTrue(tested_risk_documentation[permission].endswith(".md"))

    def test_every_permission_is_in_exactly_one_category(self) -> None:
        permissions = [
            "*",
            "iam:GetUser",
            "s3:Get*",
            "ec2:RunInstances",
            "madeup:UnknownAction",
            "s3:Get*",
        ]
        categories = classify_all("aws", permissions, unknown_default="medium")
        flattened = [permission for values in categories.values() for permission in values]
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertEqual(set(flattened), set(permissions))

    def test_legacy_sensitive_actions_upgrade_catalog_levels(self) -> None:
        instance = CloudPEASS(
            very_sensitive_combinations,
            sensitive_combinations,
            "AWS",
            1,
        )
        permissions = {
            "codebuild:StartBuild",
            "CODEBUILD:startbuildbatch",
            "lambda:InvokeFunction",
            "ec2:RunInstances",
            "codeartifact:GetAuthorizationToken",
            "sts:GetServiceBearerToken",
            "iam:GetUser",
        }
        result = instance.analyze_group(
            frozenset(permissions),
            [CloudResource("account", "account", "account", list(permissions))],
        )
        categories = result["permissions_cat"]
        self.assertIn("codebuild:StartBuild", categories["critical"])
        self.assertIn("CODEBUILD:startbuildbatch", categories["critical"])
        self.assertIn("lambda:InvokeFunction", categories["high"])
        self.assertIn("ec2:RunInstances", categories["high"])
        self.assertIn("codeartifact:GetAuthorizationToken", categories["critical"])
        self.assertIn("sts:GetServiceBearerToken", categories["critical"])
        self.assertIn("iam:GetUser", categories["low"])
        flattened = [permission for values in categories.values() for permission in values]
        self.assertEqual(len(flattened), len(set(flattened)))


def test_aws_rules_have_a_bundled_permissionless_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(risk_classifier, "_cache_dir", lambda: tmp_path / "empty-cache")
    monkeypatch.setattr(risk_classifier, "_download_risk_rules", lambda provider: None)

    data = risk_classifier._load_yaml("aws")

    assert "iam:PassRole" in data["critical_exact"]
    assert "Get" in data["read_prefixes"]
    assert data["provider"] == "aws"


def test_malformed_download_uses_bundled_aws_rules(monkeypatch, tmp_path):
    monkeypatch.setattr(risk_classifier, "_cache_dir", lambda: tmp_path / "bad-cache")
    monkeypatch.setattr(risk_classifier, "_download_risk_rules", lambda provider: "[")

    data = risk_classifier._load_yaml("aws")

    assert "kms:Decrypt" in data["critical_exact"]


def test_unwritable_cache_still_uses_bundled_aws_rules(monkeypatch, tmp_path):
    monkeypatch.setattr(risk_classifier, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(risk_classifier, "_download_risk_rules", lambda provider: None)

    original_mkdir = Path.mkdir

    def fail_for_cache(path, *args, **kwargs):
        if path == tmp_path / "cache":
            raise PermissionError("read-only cache")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_for_cache)

    data = risk_classifier._load_yaml("aws")

    assert "iam:PassRole" in data["critical_exact"]


def test_azure_rules_have_a_bundled_permissionless_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(risk_classifier, "_cache_dir", lambda: tmp_path / "empty-cache")
    monkeypatch.setattr(risk_classifier, "_download_risk_rules", lambda provider: None)

    data = risk_classifier._load_yaml("azure")

    assert data["provider"] == "azure"
    assert "listsecrets" in data["credential_action_regex"]


def test_azure_bundled_rules_are_not_relabelled_by_remote_cache(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "azure.yaml").write_text(
        "provider: azure\ncredential_action_regex: '$^'\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(risk_classifier, "_cache_dir", lambda: cache)
    monkeypatch.setattr(risk_classifier, "_download_risk_rules", lambda provider: None)

    data = risk_classifier._load_yaml("azure")

    assert "listsecrets" in data["credential_action_regex"]


def test_invalid_downloaded_aws_regex_cannot_replace_bundled_baseline(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(risk_classifier, "_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(
        risk_classifier,
        "_download_risk_rules",
        lambda provider: "provider: aws\nwrite_like_prefix_regex: '['\n",
    )

    data = risk_classifier._load_yaml("aws")

    assert data["write_like_prefix_regex"].startswith("^(Put|")


if __name__ == "__main__":
    unittest.main()
