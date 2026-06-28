import re
import unittest
from typing import Optional

from CloudPEASS.permission_risk_classifier import AzureRules, azure_regex_classify


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

    def test_resource_type_wildcards_are_not_automatically_critical(self) -> None:
        self.assertEqual(self.classify("Microsoft.HybridCompute/licenses/*"), "medium")
        self.assertEqual(self.classify("Microsoft.Insights/actionGroups/*"), "medium")
        self.assertEqual(self.classify("Microsoft.Compute/virtualMachines/*"), "medium")

    def test_wildcards_keep_maximum_risk_from_likely_child_verbs(self) -> None:
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/secrets/read"), "critical")
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/secrets/write"), "high")
        self.assertEqual(self.classify("Microsoft.KeyVault/vaults/secrets/*"), "critical")

    def test_known_privilege_escalation_wildcards_stay_critical(self) -> None:
        self.assertEqual(self.classify("Microsoft.Authorization/roleAssignments/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Authorization/roleDefinitions/*"), "critical")
        self.assertEqual(self.classify("Microsoft.ManagedIdentity/userAssignedIdentities/*"), "critical")
        self.assertEqual(self.classify("Microsoft.Storage/storageAccounts/*"), "critical")


if __name__ == "__main__":
    unittest.main()
