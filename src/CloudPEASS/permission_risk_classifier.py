"""
Permission risk classifier for AWS, Azure, and GCP.
Adapted from Blue-PEASS for CloudPEASS integration.
Loads bundled risk rules and refreshes them from Blue-CloudPEASS when possible.

Note: The Blue-CloudPEASS repository must be publicly accessible at:
https://github.com/peass-ng/Blue-CloudPEASS
"""

from __future__ import annotations

import fnmatch
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import requests
import yaml


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RISK_LEVELS = ("low", "medium", "high", "critical")

# Blue-CloudPEASS GitHub repository base URL
# Note: Update this to match your Blue-CloudPEASS repository name and branch
BLUEPEASS_RISK_RULES_BASE_URL = "https://raw.githubusercontent.com/peass-ng/Blue-CloudPEASS/refs/heads/main/risk_rules"
RISK_RULES_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


def _cache_dir() -> Path:
    """Get cache directory for risk rules."""
    return Path.home() / ".cache" / "cloudpeass" / "risk_rules"


def _bundled_rules_path(provider: str) -> Path:
    """Return the permissionless/offline baseline shipped with CloudPEASS."""
    return Path(__file__).resolve().parent / "risk_rules" / f"{provider}.yaml"


def _parse_rules_yaml(yaml_text: Optional[str], provider: str, source: str) -> dict:
    if not yaml_text:
        return {}
    try:
        data = yaml.safe_load(yaml_text) or {}
    except Exception as e:
        print(f"Warning: Couldn't parse {source} risk rules for {provider}: {e}")
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _should_refresh_cache(path: Path) -> bool:
    """Check if cached file should be refreshed."""
    if not path.exists():
        return True
    try:
        age_seconds = time.time() - path.stat().st_mtime
    except OSError:
        return True
    return age_seconds > RISK_RULES_CACHE_TTL_SECONDS


def _download_risk_rules(provider: str) -> Optional[str]:
    """Download risk rules YAML from Blue-PEASS repo."""
    url = f"{BLUEPEASS_RISK_RULES_BASE_URL}/{provider}.yaml"
    try:
        resp = requests.get(url, timeout=45)
    except Exception as e:
        print(f"Warning: Couldn't download risk rules for {provider}: {e}")
        return None

    if resp.status_code != 200:
        print(f"Warning: Couldn't download risk rules for {provider} ({resp.status_code})")
        return None
    return resp.text


def _load_yaml(provider: str) -> dict:
    """Load rules from the network/cache plus the bundled offline baseline."""
    cache_path = _cache_dir() / f"{provider}.yaml"
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Read-only homes/containers must still be able to use bundled rules.
        pass

    yaml_text = None
    downloaded_data = {}
    
    # Download if cache is stale
    if _should_refresh_cache(cache_path):
        downloaded_text = _download_risk_rules(provider)
        downloaded_data = _parse_rules_yaml(
            downloaded_text, provider, "downloaded"
        )
        if downloaded_data:
            yaml_text = downloaded_text
            try:
                cache_path.write_text(yaml_text, encoding="utf-8")
            except OSError:
                pass

    # Fallback to cached version
    if yaml_text is None and cache_path.exists():
        try:
            yaml_text = cache_path.read_text(encoding="utf-8")
        except OSError:
            pass

    bundled_path = _bundled_rules_path(provider)
    try:
        bundled_text = bundled_path.read_text(encoding="utf-8")
    except OSError:
        bundled_text = None

    bundled_data = _parse_rules_yaml(bundled_text, provider, "bundled")
    external_data = downloaded_data or _parse_rules_yaml(
        yaml_text, provider, "cached"
    )
    # Azure and GCP ship catalog-audited rule sets with CloudPEASS. Keep their
    # severity decisions deterministic: a stale user cache or a temporarily
    # different upstream revision must not silently relabel the same scan.
    if provider in {"azure", "gcp"} and bundled_data:
        return bundled_data
    if not bundled_data:
        return external_data
    if not external_data:
        return bundled_data

    # Remote rules can tune scalar heuristics, while bundled list entries remain
    # a minimum safety baseline if a remote revision accidentally omits one.
    merged = dict(bundled_data)
    for key, value in external_data.items():
        if key in {
            "write_like_prefix_regex",
            "bulk_medium_write_prefix_regex",
            "dangerous_write_regex",
            "service_medium_dangerous_regex",
        }:
            try:
                re.compile(str(value))
            except re.error as exc:
                print(
                    f"Warning: Ignoring invalid downloaded risk regex "
                    f"{key}={value!r}: {exc}"
                )
                continue
        if isinstance(value, list) and isinstance(merged.get(key), list):
            combined = list(merged[key])
            for item in value:
                if item not in combined:
                    combined.append(item)
            merged[key] = combined
        else:
            merged[key] = value
    return merged


@dataclass(frozen=True)
class AwsRules:
    critical_exact: set[str]
    low_exact: set[str]
    high_exact: set[str]
    medium_override_exact: set[str]
    high_override_exact: set[str]
    critical_exact_lower: set[str]
    low_exact_lower: set[str]
    high_exact_lower: set[str]
    medium_override_exact_lower: set[str]
    high_override_exact_lower: set[str]
    benign_write_medium_action_re: tuple[re.Pattern[str], ...]
    write_like_prefix_re: re.Pattern[str]
    dangerous_write_re: re.Pattern[str]
    sensitive_read_substrings: tuple[str, ...]
    sensitive_read_substrings_lower: tuple[str, ...]
    iam_critical_verbs: set[str]
    iam_critical_verbs_lower: set[str]
    read_prefixes: tuple[str, ...]
    medium_prefixes: tuple[str, ...]
    high_prefixes: tuple[str, ...]
    read_prefixes_lower: tuple[str, ...]
    medium_prefixes_lower: tuple[str, ...]
    high_prefixes_lower: tuple[str, ...]
    resource_policy_verbs: set[str]
    resource_policy_suffixes: tuple[str, ...]
    resource_policy_prefixes: tuple[str, ...]
    resource_policy_verbs_lower: set[str]
    resource_policy_suffixes_lower: tuple[str, ...]
    resource_policy_prefixes_lower: tuple[str, ...]


@dataclass(frozen=True)
class GcpRules:
    critical_suffixes: tuple[str, ...]
    critical_exact: set[str]
    high_suffixes: tuple[str, ...]
    high_exact: set[str]
    medium_exact: set[str]
    low_exact: set[str]
    low_verbs: set[str]
    medium_verbs: set[str]
    high_verbs: set[str]
    iam_roles_critical_verbs: set[str]
    iam_roles_medium_verbs: set[str]
    override_medium_suffixes: tuple[str, ...]
    override_medium_prefixes: tuple[str, ...]
    sensitive_read_keywords: tuple[str, ...]
    dangerous_write_keywords: tuple[str, ...]
    dangerous_write_keywords_lower: tuple[str, ...]


@dataclass(frozen=True)
class AzureRules:
    credential_action_re: re.Pattern[str]
    storage_insights_child_re: re.Pattern[str]
    register_like_action_re: re.Pattern[str]
    provider_diagnostic_settings_write_re: re.Pattern[str]
    boundary_keywords: tuple[str, ...]
    cost_mgmt_exact_medium: set[str]
    insights_exclude_keywords: tuple[str, ...]
    insights_medium_prefixes_write: tuple[str, ...]
    insights_medium_prefixes_write_or_action: tuple[str, ...]
    insights_activitylogalerts_prefix: str
    insights_alertrules_prefix: str
    medium_write_action_provider_prefixes: tuple[str, ...]
    resourcehealth_events_action_prefix: str
    billing_provider_prefix: str
    billing_exclude_keywords: tuple[str, ...]
    appinsights_component_prefix: str
    appinsights_exclude_keywords: tuple[str, ...]
    dangerous_write_keywords: tuple[str, ...]
    dangerous_write_keywords_lower: tuple[str, ...]


# AzurePEASS also emits Microsoft Graph scopes, Entra role actions, ownership
# evidence, and CLI capability labels.  Keep core safety rules in code so an
# offline scan does not depend on the optional Blue-CloudPEASS YAML download.
_AZURE_CRITICAL_EXACT = frozenset(
    {
        "microsoft.authorization/elevateaccess/action",
        "microsoft.authorization/roleassignments/write",
        "microsoft.authorization/roleassignmentschedules/write",
        "microsoft.authorization/roleassignmentschedulerequests/write",
        "microsoft.authorization/roleeligibilityschedulerequests/write",
        "microsoft.keyvault/vaults/accesspolicies/write",
        "microsoft.keyvault/vaults/secrets/getsecret/action",
        "microsoft.keyvault/vaults/keys/decrypt/action",
        "microsoft.keyvault/vaults/keys/unwrap/action",
        "microsoft.keyvault/vaults/keys/unwrapkey/action",
        "microsoft.keyvault/vaults/keys/sign/action",
        "microsoft.compute/virtualmachines/extensions/write",
        "microsoft.compute/virtualmachines/runcommand/action",
        "microsoft.compute/virtualmachines/runcommands/write",
        "microsoft.compute/virtualmachines/loginasadmin/action",
        "microsoft.compute/virtualmachinescalesets/virtualmachines/runcommands/write",
        "microsoft.hybridcompute/machines/runcommands/write",
        "microsoft.containerinstance/containergroups/containers/exec/action",
        # Live validation recovered Function administration credentials and
        # used them to invoke a key-protected function or deploy code to a
        # slot. Slot config/list also exposed a reusable Storage account key.
        "microsoft.web/sites/functions/masterkey/read",
        "microsoft.web/sites/functions/token/read",
        "microsoft.web/sites/slots/publishxml/action",
        "microsoft.web/sites/slots/config/list/action",
        # Live validation confirmed that start/action accepts a per-execution
        # container image and command override, providing code execution in the
        # target Job's identity and network context without jobs/write.
        "microsoft.app/jobs/start/action",
        # These actions returned reusable credentials or cleartext inline
        # secrets during live validation.
        "microsoft.app/jobs/listsecrets/action",
        "microsoft.app/managedenvironments/daprcomponents/listsecrets/action",
        "microsoft.devices/provisioningservices/listkeys/action",
        "microsoft.devices/provisioningservices/keys/listkeys/action",
        # Live validation recovered credentials and used them against the
        # corresponding data planes: Static Web Apps deployment, Language,
        # Storage through Azure ML, and protected Functions.
        "microsoft.web/staticsites/listsecrets/action",
        "microsoft.cognitiveservices/accounts/listkeys/action",
        # These long-standing credential paths are also configured as
        # singleton critical attacks in sensitive_permissions.azure. Keep the
        # standalone classifier aligned without promoting every unknown action
        # merely because its name contains "keys".
        "microsoft.appconfiguration/configurationstores/listkeys/action",
        "microsoft.devices/iothubs/listkeys/action",
        "microsoft.machinelearningservices/workspaces/listkeys/action",
        "microsoft.machinelearningservices/workspaces/liststorageaccountkeys/action",
        "microsoft.machinelearningservices/workspaces/connections/listsecrets/action",
        "microsoft.machinelearningservices/workspaces/datastores/listsecrets/action",
        "microsoft.web/sites/host/listkeys/action",
        "microsoft.web/sites/functions/listkeys/action",
        "microsoft.web/sites/functions/listsecrets/action",
        # Foundry account/project connections returned a stored Cognitive
        # Services key that successfully called the connected Language API.
        "microsoft.cognitiveservices/accounts/connections/listsecrets/action",
        "microsoft.cognitiveservices/accounts/projects/connections/listsecrets/action",
        # APIM returned a cleartext Named Value, OAuth/OIDC client secrets,
        # and even a Function master key embedded in backend credentials.
        "microsoft.apimanagement/service/namedvalues/listvalue/action",
        "microsoft.apimanagement/service/backends/read",
        "microsoft.apimanagement/service/authorizationservers/listsecrets/action",
        "microsoft.apimanagement/service/openidconnectproviders/listsecrets/action",
        "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write",
        "microsoft.web/sites/config/list/action",
        "microsoft.web/sites/publishxml/action",
        "microsoft.storage/storageaccounts/listaccountsas/action",
        "microsoft.storage/storageaccounts/listservicesas/action",
        # Regenerated admin keys permit full Search data-plane reads and writes.
        "microsoft.search/searchservices/regenerateadminkey/action",
        # Default Notification Hubs management rules expose device registration
        # data and permit arbitrary notification delivery.
        "microsoft.notificationhubs/namespaces/authorizationrules/listkeys/action",
        "microsoft.notificationhubs/namespaces/authorizationrules/regeneratekeys/action",
        "microsoft.notificationhubs/namespaces/notificationhubs/authorizationrules/listkeys/action",
        "microsoft.notificationhubs/namespaces/notificationhubs/authorizationrules/regeneratekeys/action",
    }
)

_AZURE_HIGH_EXACT = frozenset(
    {
        "microsoft.eventgrid/domains/listkeys/action",
        "microsoft.eventgrid/domains/regeneratekey/action",
        "microsoft.eventgrid/namespaces/listkeys/action",
        "microsoft.eventgrid/namespaces/regeneratekey/action",
        "microsoft.eventgrid/namespaces/topics/listkeys/action",
        "microsoft.eventgrid/namespaces/topics/regeneratekey/action",
        "microsoft.eventgrid/partnernamespaces/listkeys/action",
        "microsoft.eventgrid/partnernamespaces/regeneratekey/action",
        "microsoft.eventgrid/topics/listkeys/action",
        "microsoft.eventgrid/topics/regeneratekey/action",
        "microsoft.operationalinsights/workspaces/listkeys/action",
        "microsoft.operationalinsights/workspaces/regeneratesharedkey/action",
        "microsoft.operationalinsights/workspaces/sharedkeys/action",
        "microsoft.operationalinsights/workspaces/sharedkeys/read",
        # Live validation confirmed credential use against these data planes.
        # Their escalation impact still depends on the application or relay
        # connected to the service, so do not promote them to critical solely
        # because the operation name contains keys.
        "microsoft.communication/communicationservices/listkeys/action",
        "microsoft.communication/communicationservices/regeneratekey/action",
        "microsoft.relay/namespaces/authorizationrules/listkeys/action",
        "microsoft.relay/namespaces/authorizationrules/regeneratekeys/action",
        "microsoft.relay/namespaces/hybridconnections/authorizationrules/listkeys/action",
        "microsoft.relay/namespaces/hybridconnections/authorizationrules/regeneratekeys/action",
        "microsoft.relay/namespaces/wcfrelays/authorizationrules/listkeys/action",
        "microsoft.relay/namespaces/wcfrelays/authorizationrules/regeneratekeys/action",
        "microsoft.signalrservice/signalr/listkeys/action",
        "microsoft.signalrservice/signalr/regeneratekey/action",
        "microsoft.signalrservice/webpubsub/listkeys/action",
        "microsoft.signalrservice/webpubsub/regeneratekey/action",
        # These live-tested credentials or signed callbacks reached only the
        # configured API, bot, map service, artifact, or workflow. Their exact
        # downstream impact is configuration-dependent, so keep them High.
        "microsoft.maps/accounts/listkeys/action",
        "microsoft.botservice/botservices/channels/listchannelwithkeys/action",
        "microsoft.apimanagement/service/subscriptions/listsecrets/action",
        "microsoft.logic/integrationaccounts/listcallbackurl/action",
        "microsoft.logic/integrationaccounts/agreements/listcontentcallbackurl/action",
        "microsoft.logic/integrationaccounts/assemblies/listcontentcallbackurl/action",
        "microsoft.logic/integrationaccounts/maps/listcontentcallbackurl/action",
        "microsoft.logic/integrationaccounts/partners/listcontentcallbackurl/action",
        "microsoft.logic/integrationaccounts/schemas/listcontentcallbackurl/action",
        "microsoft.logic/workflows/listcallbackurl/action",
        "microsoft.authorization/roledefinitions/write",
        "microsoft.compute/virtualmachines/login/action",
        "microsoft.containerservice/managedclusters/listclusterusercredential/action",
        "microsoft.hybridcontainerservice/provisionedclusters/listclusterusercredential/action",
        "microsoft.kubernetes/connectedclusters/listclusterusercredential/action",
        "microsoft.kubernetes/connectedclusters/listclusterusercredentials/action",
        # These credentials provide account-wide or service-wide read access
        # to potentially sensitive data but do not authorize data writes.
        "microsoft.search/searchservices/createquerykey/action",
        "microsoft.search/searchservices/listquerykeys/action",
        "microsoft.documentdb/databaseaccounts/readonlykeys/action",
        "microsoft.documentdb/databaseaccounts/readonlykeys/read",
        # These operations execute an existing workflow or pipeline. Their
        # impact depends on the stored actions and identities, but can include
        # privileged side effects and access to sensitive downstream data.
        "microsoft.logic/workflows/triggers/listcallbackurl/action",
        "microsoft.logic/workflows/versions/triggers/listcallbackurl/action",
        "microsoft.logic/workflows/triggers/run/action",
        "microsoft.logic/workflows/triggers/histories/resubmit/action",
        "microsoft.datafactory/factories/pipelines/createrun/action",
        # getFullUrl returned signed Logic App callback URLs that were usable
        # without the caller's Entra token. ACR run-log SAS URLs similarly
        # exposed a seeded build-log canary.
        "microsoft.eventgrid/eventsubscriptions/getfullurl/action",
        "microsoft.eventgrid/topics/eventsubscriptions/getfullurl/action",
        "microsoft.eventgrid/systemtopics/eventsubscriptions/getfullurl/action",
        "microsoft.eventgrid/domains/eventsubscriptions/getfullurl/action",
        "microsoft.eventgrid/domains/topics/eventsubscriptions/getfullurl/action",
        "microsoft.containerregistry/registries/runs/listlogsasurl/action",
        # Live validation recovered stored signed callback URLs or literal
        # credentials and used each one against the protected canary. These
        # reads/actions are configuration-dependent, so they remain High.
        "microsoft.insights/actiongroups/read",
        "microsoft.insights/webtests/read",
        "microsoft.containerregistry/registries/webhooks/getcallbackconfig/action",
        "microsoft.apimanagement/service/policies/read",
        "microsoft.apimanagement/service/apis/policies/read",
        "microsoft.apimanagement/service/apis/operations/policies/read",
        "microsoft.apimanagement/service/products/policies/read",
        # The normal VPN configuration GET redacts RADIUS secrets; this
        # dedicated action returned the exact configured shared secret.
        "microsoft.network/vpnserverconfigurations/listallradiusserverssecrets/action",
        # Both ARM paths returned a seeded cleartext application secret from
        # a Free App Configuration store, without requiring data-plane RBAC.
        "microsoft.appconfiguration/configurationstores/listkeyvalue/action",
        "microsoft.appconfiguration/configurationstores/keyvalues/read",
        # A read SAS from each operation was live-tested by downloading a
        # seeded byte range from the raw managed VHD. This exposes the complete
        # disk/snapshot without requiring attachment to an attacker VM.
        "microsoft.compute/disks/begingetaccess/action",
        "microsoft.compute/snapshots/begingetaccess/action",
        "microsoft.compute/restorepointcollections/restorepoints/diskrestorepoints/begingetaccess/action",
        "microsoft.managedidentity/userassignedidentities/assign/action",
        "microsoft.app/containerapps/getauthtoken/action",
        "microsoft.resources/deploymentscripts/write",
        "microsoft.web/staticsites/createinvitation/action",
    }
)

_AZURE_MEDIUM_EXACT = frozenset(
    {
        # Creating or updating the identity object does not attach it to a
        # workload and does not grant control of an existing identity.
        "microsoft.managedidentity/userassignedidentities/write",
        "microsoft.keyvault/vaults/certificates/purge/action",
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/move/action",
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/permanentdelete/action",
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/tags/read",
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/tags/write",
    }
)

_ENTRA_MEDIUM_EXACT = frozenset(
    {
        # These change ordinary directory object properties, not membership,
        # ownership, credentials, authentication methods, or role assignment.
        "microsoft.directory/groups/allproperties/update",
        "microsoft.directory/users/basic/update",
        "microsoft.directory/groupsassignabletoroles/allproperties/update",
    }
)

_GRAPH_CRITICAL_EXACT = frozenset(
    {
        "approleassignment.readwrite.all",
        "application.readwrite.all",
        "delegatedpermissiongrant.readwrite.all",
        "privilegedaccess.readwrite.azuread",
        "privilegedaccess.readwrite.azureresources",
        "rolemanagement.readwrite.directory",
        "userauthenticationmethod.readwrite.all",
        "devicelocalcredential.read.all",
        "bitlockerkey.read.all",
    }
)

_GRAPH_HIGH_EXACT = frozenset(
    {
        "auditlog.read.all",
        "directory.accessasuser.all",
        "directory.read.all",
        "directory.readwrite.all",
        "group.readwrite.all",
        "mail.read",
        "mail.readwrite",
        "mail.send",
        "rolemanagement.read.directory",
        "user.read.all",
        "user.readwrite.all",
    }
)

_GRAPH_MEDIUM_EXACT = frozenset(
    {
        # These become critical only as the documented two-permission
        # Conditional Access combination. Neither can change a policy alone.
        "application.read.all",
        "policy.readwrite.conditionalaccess",
    }
)

_GRAPH_LOW_EXACT = frozenset(
    {
        "email",
        "offline_access",
        "openid",
        "profile",
        "user.read",
    }
)

_GRAPH_SENSITIVE_DATA_PREFIXES = (
    "calendars.",
    "channelmessage.",
    "chat.",
    "contacts.",
    "files.",
    "mail.",
    "notes.",
    "sites.",
    "tasks.",
    "teamwork.",
)

_AZURE_CRITICAL_WILDCARD_BASES = frozenset(
    {
        "microsoft.authorization/roleassignments",
        "microsoft.app/containerapps",
        "microsoft.app/jobs",
        "microsoft.compute/virtualmachines",
        "microsoft.compute/virtualmachines/extensions",
        "microsoft.compute/virtualmachines/runcommands",
        "microsoft.compute/virtualmachinescalesets/virtualmachines",
        "microsoft.compute/virtualmachinescalesets/virtualmachines/runcommands",
        "microsoft.containerservice/managedclusters",
        "microsoft.containerservice/managedclusters/accessprofiles",
        "microsoft.hybridcompute/machines",
        "microsoft.hybridcompute/machines/runcommands",
        "microsoft.keyvault/vaults",
        "microsoft.keyvault/vaults/keys",
        "microsoft.keyvault/vaults/secrets",
        "microsoft.managedidentity/userassignedidentities",
        "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials",
        "microsoft.search/searchservices",
        "microsoft.storage/storageaccounts",
        "microsoft.storage/storageaccounts/localusers",
        "microsoft.web/sites",
        "microsoft.web/sites/config",
        "microsoft.web/sites/functions",
        "microsoft.web/sites/host",
        "microsoft.web/sites/slots",
        "microsoft.web/sites/slots/config",
        "microsoft.web/sites/slots/functions",
        "microsoft.web/sites/slots/host",
    }
)

# Provider-root wildcards are severe only when the current ARM operation
# catalog contains a concrete credential, execution, authorization, or
# sensitive-data primitive for that provider. Unknown/operational namespaces
# stay medium until there is evidence for promoting them.
_AZURE_CRITICAL_PROVIDER_ROOTS = frozenset(
    {
        "microsoft.apimanagement",
        "microsoft.app",
        "microsoft.appconfiguration",
        "microsoft.appplatform",
        "microsoft.authorization",
        "microsoft.automation",
        "microsoft.azuredatatransfer",
        "microsoft.azurestack",
        "microsoft.azurestackhci",
        "microsoft.batch",
        "microsoft.billingtrust",
        "microsoft.bing",
        "microsoft.botservice",
        "microsoft.cache",
        "microsoft.cognitiveservices",
        "microsoft.communication",
        "microsoft.compute",
        "microsoft.containerinstance",
        "microsoft.containerregistry",
        "microsoft.containerservice",
        "microsoft.databox",
        "microsoft.databoxedge",
        "microsoft.datafactory",
        "microsoft.datadog",
        "microsoft.datamigration",
        "microsoft.dbformysql",
        "microsoft.dbforpostgresql",
        "microsoft.desktopvirtualization",
        "microsoft.devices",
        "microsoft.documentdb",
        "microsoft.edgemarketplace",
        "microsoft.edgeorder",
        "microsoft.elastic",
        "microsoft.eventgrid",
        "microsoft.eventhub",
        "microsoft.fluidrelay",
        "microsoft.healthbot",
        "microsoft.hybridcompute",
        "microsoft.hybridconnectivity",
        "microsoft.hybridcontainerservice",
        "microsoft.hybridnetwork",
        "microsoft.impact",
        "microsoft.inferenceservice",
        "microsoft.keyvault",
        "microsoft.kubernetesconfiguration",
        "microsoft.logic",
        "microsoft.machinelearningservices",
        "microsoft.managedidentity",
        "microsoft.maps",
        "microsoft.netapp",
        "microsoft.network",
        "microsoft.notificationhubs",
        "microsoft.operationalinsights",
        "microsoft.purview",
        "microsoft.quantum",
        "microsoft.redhatopenshift",
        "microsoft.relay",
        "microsoft.resourceconnector",
        "microsoft.saas",
        "microsoft.search",
        "microsoft.securitydetonation",
        "microsoft.servicebus",
        "microsoft.signalrservice",
        "microsoft.softwareplan",
        "microsoft.sql",
        "microsoft.storage",
        "microsoft.synapse",
        "microsoft.videoindexer",
        "microsoft.web",
    }
)

_AZURE_HIGH_PROVIDER_ROOTS = frozenset(
    {
        "microsoft.cdn",
        "microsoft.certificateregistration",
        "microsoft.dbformariadb",
        "microsoft.devtestlab",
        "microsoft.kubernetes",
        "microsoft.recoveryservices",
        "microsoft.resources",
        "nginx.nginxplus",
        "paloaltonetworks.cloudngfw",
    }
)


_AWS_RULES: Optional[AwsRules] = None
_GCP_RULES: Optional[GcpRules] = None
_AZURE_RULES: Optional[AzureRules] = None


def load_rules(provider: str):
    global _AWS_RULES, _GCP_RULES, _AZURE_RULES
    provider = provider.lower().strip()
    if provider == "aws":
        if _AWS_RULES is not None:
            return _AWS_RULES
        data = _load_yaml("aws")
        critical_exact = set(data.get("critical_exact") or [])
        low_exact = set(data.get("low_exact") or [])
        high_exact = set(data.get("high_exact") or [])
        medium_override_exact = set(data.get("medium_override_exact") or [])
        high_override_exact = set(data.get("high_override_exact") or [])
        ignored_sensitive_read_substrings = {
            str(value).casefold()
            for value in (data.get("ignored_sensitive_read_substrings") or [])
        }
        sensitive_read_substrings = tuple(
            value
            for value in (data.get("sensitive_read_substrings") or [])
            if str(value).casefold() not in ignored_sensitive_read_substrings
        )
        read_prefixes = tuple(data.get("read_prefixes") or [])
        medium_prefixes = tuple(data.get("medium_prefixes") or [])
        high_prefixes = tuple(data.get("high_prefixes") or [])
        resource_policy_verbs = set(data.get("resource_policy_verbs") or [])
        resource_policy_suffixes = tuple(data.get("resource_policy_suffixes") or [])
        resource_policy_prefixes = tuple(data.get("resource_policy_prefixes") or [])

        write_like_prefix_regex = data.get("write_like_prefix_regex") or data.get("bulk_medium_write_prefix_regex") or r"^$"
        dangerous_write_regex = data.get("dangerous_write_regex") or data.get("service_medium_dangerous_regex") or r"$^"

        _AWS_RULES = AwsRules(
            critical_exact=critical_exact,
            low_exact=low_exact,
            high_exact=high_exact,
            medium_override_exact=medium_override_exact,
            high_override_exact=high_override_exact,
            critical_exact_lower={x.lower() for x in critical_exact},
            low_exact_lower={x.lower() for x in low_exact},
            high_exact_lower={x.lower() for x in high_exact},
            medium_override_exact_lower={x.lower() for x in medium_override_exact},
            high_override_exact_lower={x.lower() for x in high_override_exact},
            benign_write_medium_action_re=_compile_regex_list(
                data.get("benign_write_medium_action_regex") or []
            ),
            write_like_prefix_re=_compile_regex(
                write_like_prefix_regex,
                r"^$",
            ),
            dangerous_write_re=_compile_regex(
                dangerous_write_regex,
                r"$^",
            ),
            sensitive_read_substrings=sensitive_read_substrings,
            sensitive_read_substrings_lower=tuple(s.lower() for s in sensitive_read_substrings),
            iam_critical_verbs=set(data.get("iam_critical_verbs") or []),
            iam_critical_verbs_lower={str(v).lower() for v in (data.get("iam_critical_verbs") or [])},
            read_prefixes=read_prefixes,
            medium_prefixes=medium_prefixes,
            high_prefixes=high_prefixes,
            read_prefixes_lower=tuple(p.lower() for p in read_prefixes),
            medium_prefixes_lower=tuple(p.lower() for p in medium_prefixes),
            high_prefixes_lower=tuple(p.lower() for p in high_prefixes),
            resource_policy_verbs=resource_policy_verbs,
            resource_policy_suffixes=resource_policy_suffixes,
            resource_policy_prefixes=resource_policy_prefixes,
            resource_policy_verbs_lower={v.lower() for v in resource_policy_verbs},
            resource_policy_suffixes_lower=tuple(s.lower() for s in resource_policy_suffixes),
            resource_policy_prefixes_lower=tuple(p.lower() for p in resource_policy_prefixes),
        )
        return _AWS_RULES
    if provider == "gcp":
        if _GCP_RULES is not None:
            return _GCP_RULES
        data = _load_yaml("gcp")
        dangerous_write_keywords = tuple(data.get("dangerous_write_keywords") or [])
        low_verbs = {str(v).lower() for v in (data.get("low_verbs") or [])}
        medium_verbs = {str(v).lower() for v in (data.get("medium_verbs") or [])}
        high_verbs = {str(v).lower() for v in (data.get("high_verbs") or [])}
        iam_roles_critical_verbs = {str(v).lower() for v in (data.get("iam_roles_critical_verbs") or [])}
        iam_roles_medium_verbs = {str(v).lower() for v in (data.get("iam_roles_medium_verbs") or [])}
        _GCP_RULES = GcpRules(
            critical_suffixes=tuple(
                str(value).lower() for value in (data.get("critical_suffixes") or [])
            ),
            critical_exact=set(data.get("critical_exact") or []),
            high_suffixes=tuple(
                str(value).lower() for value in (data.get("high_suffixes") or [])
            ),
            high_exact=set(data.get("high_exact") or []),
            medium_exact=set(data.get("medium_exact") or []),
            low_exact=set(data.get("low_exact") or []),
            low_verbs=low_verbs,
            medium_verbs=medium_verbs,
            high_verbs=high_verbs,
            iam_roles_critical_verbs=iam_roles_critical_verbs,
            iam_roles_medium_verbs=iam_roles_medium_verbs,
            override_medium_suffixes=tuple(data.get("override_medium_suffixes") or []),
            override_medium_prefixes=tuple(data.get("override_medium_prefixes") or []),
            sensitive_read_keywords=tuple(data.get("sensitive_read_keywords") or []),
            dangerous_write_keywords=dangerous_write_keywords,
            dangerous_write_keywords_lower=tuple(k.lower() for k in dangerous_write_keywords),
        )
        return _GCP_RULES
    if provider == "azure":
        if _AZURE_RULES is not None:
            return _AZURE_RULES
        data = _load_yaml("azure")
        dangerous_write_keywords = tuple(data.get("dangerous_write_keywords") or [])
        _AZURE_RULES = AzureRules(
            credential_action_re=re.compile(data.get("credential_action_regex") or r"$^", re.IGNORECASE),
            storage_insights_child_re=re.compile(data.get("storage_insights_child_regex") or r"$^", re.IGNORECASE),
            register_like_action_re=re.compile(data.get("register_like_action_regex") or r"$^", re.IGNORECASE),
            provider_diagnostic_settings_write_re=re.compile(
                data.get("provider_diagnostic_settings_write_regex") or r"$^", re.IGNORECASE
            ),
            boundary_keywords=tuple(data.get("boundary_keywords") or []),
            cost_mgmt_exact_medium=set(data.get("cost_mgmt_exact_medium") or []),
            insights_exclude_keywords=tuple(data.get("insights_exclude_keywords") or []),
            insights_medium_prefixes_write=tuple(data.get("insights_medium_prefixes_write") or []),
            insights_medium_prefixes_write_or_action=tuple(data.get("insights_medium_prefixes_write_or_action") or []),
            insights_activitylogalerts_prefix=str(data.get("insights_activitylogalerts_prefix") or ""),
            insights_alertrules_prefix=str(data.get("insights_alertrules_prefix") or ""),
            medium_write_action_provider_prefixes=tuple(data.get("medium_write_action_provider_prefixes") or []),
            resourcehealth_events_action_prefix=str(data.get("resourcehealth_events_action_prefix") or ""),
            billing_provider_prefix=str(data.get("billing_provider_prefix") or ""),
            billing_exclude_keywords=tuple(data.get("billing_exclude_keywords") or []),
            appinsights_component_prefix=str(data.get("appinsights_component_prefix") or ""),
            appinsights_exclude_keywords=tuple(data.get("appinsights_exclude_keywords") or []),
            dangerous_write_keywords=dangerous_write_keywords,
            dangerous_write_keywords_lower=tuple(k.lower() for k in dangerous_write_keywords),
        )
        return _AZURE_RULES
    raise ValueError(f"Unknown provider: {provider}")


def _aws_is_nondangerous_write(action: str, rules: AwsRules) -> bool:
    if ":" not in action:
        return False
    _, verb = action.split(":", 1)
    verb = verb.strip()
    if not rules.write_like_prefix_re.match(verb):
        return False
    if rules.dangerous_write_re.search(verb):
        return False
    return True


def _startswith_any_ci(text: str, prefixes_lower: tuple[str, ...]) -> bool:
    t = text.lower()
    return t.startswith(prefixes_lower)


def _compile_regex(pattern: object, fallback: str) -> re.Pattern[str]:
    try:
        return re.compile(str(pattern), re.IGNORECASE)
    except re.error as exc:
        print(f"Warning: Ignoring invalid permission-risk regex {pattern!r}: {exc}")
        return re.compile(fallback, re.IGNORECASE)


def _compile_regex_list(patterns: object) -> tuple[re.Pattern[str], ...]:
    compiled = []
    if not isinstance(patterns, (list, tuple)):
        return ()
    for pattern in patterns:
        try:
            compiled.append(re.compile(str(pattern), re.IGNORECASE))
        except re.error as exc:
            print(f"Warning: Ignoring invalid permission-risk regex {pattern!r}: {exc}")
    return tuple(compiled)


def aws_override_level(action: str, rules: AwsRules) -> Optional[str]:
    action = action.strip()
    if not action:
        return None

    action_lower = action.lower()

    # Explicit evidence-backed high corrections must beat both stale upstream
    # critical entries and stale cached low entries.
    if action_lower in rules.high_override_exact_lower:
        return "high"
    if action_lower in rules.low_exact_lower:
        return "low"
    if action_lower in rules.medium_override_exact_lower:
        return "medium"
    if action_lower in rules.critical_exact_lower:
        return "critical"
    if action_lower in rules.high_exact_lower:
        return "high"

    if any(r.match(action) for r in rules.benign_write_medium_action_re):
        return "medium"

    # Global rule: downgrade any non-dangerous write-like action to medium.
    if _aws_is_nondangerous_write(action, rules):
        return "medium"

    return None


def _aws_pattern_matches(pattern: str, candidate: str) -> bool:
    """AWS IAM action matching is case-insensitive and supports * and ?."""
    return fnmatch.fnmatchcase(candidate.casefold(), pattern.casefold())


def _aws_wildcard_level(action: str, rules: AwsRules) -> Optional[str]:
    """Classify an IAM Action pattern by the most dangerous action it implies."""
    if not any(char in action for char in "*?"):
        return None

    action = action.strip()
    if action in {"*", "*:*"}:
        return "critical"
    if ":" not in action:
        return "critical"

    service, verb = action.split(":", 1)
    service_lower = service.casefold().strip()
    verb_lower = verb.casefold().strip()
    if service_lower == "*" or verb_lower == "*":
        return "critical"

    critical_candidates = (
        set(rules.critical_exact_lower)
        - rules.low_exact_lower
        - rules.medium_override_exact_lower
        - rules.high_override_exact_lower
    )
    critical_candidates.update(f"iam:{verb}" for verb in rules.iam_critical_verbs_lower)
    if any(_aws_pattern_matches(action, candidate) for candidate in critical_candidates):
        return "critical"
    high_candidates = rules.high_exact_lower | rules.high_override_exact_lower
    if any(_aws_pattern_matches(action, candidate) for candidate in high_candidates):
        return "high"

    # A wildcard can imply one of these well-known escalation/data actions even
    # when the exact action is supplied by the legacy sensitive-combination list.
    critical_examples = (
        "iam:PassRole",
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        "s3:PutBucketPolicy",
        "secretsmanager:GetSecretValue",
        "ssm:StartSession",
        "ssm:SendCommand",
    )
    if any(_aws_pattern_matches(action, candidate) for candidate in critical_examples):
        return "critical"

    high_examples = (
        "s3:GetObject",
        "s3:PutObject",
        "lambda:InvokeFunction",
        "ec2:RunInstances",
        "ecs:RunTask",
        "codebuild:StartBuild",
    )
    if any(_aws_pattern_matches(action, candidate) for candidate in high_examples):
        return "high"

    # Broad Get patterns may include credentials, secrets, tokens, or object
    # contents. Describe/List/View/Head patterns remain ordinary discovery.
    if verb_lower.startswith(("describe", "list", "view", "head", "batchlist")):
        return "low"
    if verb_lower.startswith(("get", "batchget")):
        return "high"
    if verb_lower.startswith(rules.medium_prefixes_lower):
        return "medium"
    if verb_lower.startswith(rules.high_prefixes_lower):
        return "high"

    # An unknown partial action pattern grants more than one operation; avoid
    # understating it as a single unknown medium action.
    return "high"


def aws_regex_classify(action: str, rules: AwsRules) -> Optional[str]:
    action = action.strip()
    if not action:
        return None

    wildcard_level = _aws_wildcard_level(action, rules)
    if wildcard_level is not None:
        return wildcard_level

    override = aws_override_level(action, rules)
    if override is not None:
        return override

    if ":" not in action:
        return None

    service, verb = action.split(":", 1)
    service = service.lower().strip()
    verb = verb.strip()
    verb_lower = verb.lower()

    if service == "iam":
        if _startswith_any_ci(verb, rules.read_prefixes_lower):
            return "low"
        if verb_lower in rules.iam_critical_verbs_lower or verb_lower == "passrole":
            return "critical"
        return "medium"

    if service == "sts" and verb_lower.startswith("assumerole"):
        return "critical"

    if verb_lower in rules.resource_policy_verbs_lower or (
        verb_lower.endswith(rules.resource_policy_suffixes_lower) and verb_lower.startswith(rules.resource_policy_prefixes_lower)
    ):
        return "high"

    # S3 is special: only object content read/write are treated as high by default.
    if service == "s3":
        if verb_lower in ("getobject", "putobject"):
            return "high"
        if verb_lower.startswith(rules.medium_prefixes_lower):
            return "medium"
        if verb_lower.startswith(rules.read_prefixes_lower) or verb_lower.startswith("batchget"):
            return "low"
        if verb_lower.startswith(rules.high_prefixes_lower):
            return "medium"
        return None

    if verb_lower.startswith(rules.medium_prefixes_lower):
        return "medium"

    if verb_lower.startswith(rules.read_prefixes_lower) or verb_lower.startswith("batchget"):
        if any(sub in verb_lower for sub in rules.sensitive_read_substrings_lower):
            return "high"
        return "low"

    if verb_lower.startswith(rules.high_prefixes_lower):
        return "medium"

    return None


def _gcp_is_sensitive_read(permission_lower: str, rules: GcpRules) -> bool:
    # IAM policy reads are discovery, not secrets/data by themselves.
    if "iampolicy" in permission_lower or "setiampolicy" in permission_lower:
        return False
    return any(k in permission_lower for k in rules.sensitive_read_keywords)


def _gcp_is_dangerous_write(permission_lower: str, rules: GcpRules) -> bool:
    return any(k in permission_lower for k in rules.dangerous_write_keywords_lower)


def gcp_override_level(permission: str, rules: GcpRules) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None
    if permission in rules.critical_exact:
        return "critical"
    if permission in rules.high_exact:
        return "high"
    if permission in rules.medium_exact:
        return "medium"
    if permission in rules.low_exact:
        return "low"

    lower = permission.lower()
    if lower.endswith(rules.override_medium_suffixes):
        if any(k in lower for k in ("iampolicy", "setiampolicy", "policy", "role", "secret", "token", "credential", "key")):
            return None
        return "medium"

    # Keep recommender updates as operational medium without making all recommender.* medium.
    if any(lower.startswith(p) for p in rules.override_medium_prefixes) and lower.endswith(".update"):
        if any(k in lower for k in ("iampolicy", "setiampolicy", "policy", "role", "secret", "token", "credential", "key")):
            return None
        return "medium"

    return None


def gcp_regex_classify(permission: str, rules: GcpRules) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    override = gcp_override_level(permission, rules)
    if override is not None:
        return override

    # Wildcards.
    if permission == "*" or permission in ("*.*", "*.*.*") or permission.endswith(".*"):
        return "critical"

    if permission in rules.critical_exact:
        return "critical"

    lower = permission.lower()

    # Hardcoded sensitive permissions.
    if lower in ("storage.objects.get", "storage.objects.create", "storage.objects.delete"):
        return "high"
    if lower.endswith(rules.critical_suffixes):
        return "critical"

    # Treat ALL `*.setIamPolicy` as privilege escalation.
    if lower.endswith(".setiampolicy"):
        return "critical"

    if lower.endswith(rules.high_suffixes):
        return "high"

    if lower.startswith("iam.roles."):
        role_verb = lower.rsplit(".", 1)[-1]
        if role_verb in rules.iam_roles_critical_verbs:
            return "critical"
        if role_verb in rules.iam_roles_medium_verbs:
            return "medium"

    if "." not in permission:
        return None

    verb = permission.rsplit(".", 1)[-1].strip()
    verb_lower = verb.lower()
    if not verb_lower:
        return None

    if verb_lower in rules.medium_verbs or any(verb_lower.startswith(v) for v in rules.medium_verbs):
        return "medium"

    if verb_lower in rules.low_verbs or any(verb_lower.startswith(v) for v in rules.low_verbs):
        if _gcp_is_sensitive_read(lower, rules):
            return "high"
        return "low"

    if verb_lower in rules.high_verbs or any(verb_lower.startswith(v) for v in rules.high_verbs):
        return "high" if _gcp_is_dangerous_write(lower, rules) else "medium"

    return None


def _azure_last_segment(permission: str) -> str:
    return permission.split("/")[-1].strip().lower()


def _azure_contains_boundary_keywords(lower: str, rules: AzureRules) -> bool:
    return any(k in lower for k in rules.boundary_keywords)


def _highest_risk(levels: Iterable[Optional[str]]) -> Optional[str]:
    best = None
    for level in levels:
        if level is None:
            continue
        if best is None or RISK_ORDER[level] > RISK_ORDER[best]:
            best = level
    return best


def azure_override_level(permission: str, rules: AzureRules) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    lower = permission.lower()

    if rules.storage_insights_child_re.match(lower):
        return "low"

    if lower.startswith("microsoft.storage/storageaccounts/") and lower.endswith("/usages/read"):
        return "low"

    if rules.register_like_action_re.search(lower):
        return "medium"

    if rules.provider_diagnostic_settings_write_re.search(lower):
        return "medium"

    if lower in rules.cost_mgmt_exact_medium:
        return "medium"

    if lower.startswith("microsoft.insights/"):
        if _azure_contains_boundary_keywords(lower, rules):
            return None
        if any(k in lower for k in rules.insights_exclude_keywords):
            return None

        if any(lower.startswith(p) for p in rules.insights_medium_prefixes_write) and lower.endswith("/write"):
            return "medium"

        if any(lower.startswith(p) for p in rules.insights_medium_prefixes_write_or_action) and lower.endswith(("/write", "/action")):
            return "medium"

        if rules.insights_activitylogalerts_prefix and lower.startswith(rules.insights_activitylogalerts_prefix) and (lower.endswith("/write") or lower.endswith("/activated/action")):
            return "medium"

        if rules.insights_alertrules_prefix and lower.startswith(rules.insights_alertrules_prefix) and lower.endswith(
            ("/write", "/activated/action", "/resolved/action", "/throttled/action")
        ):
            return "medium"

    if any(lower.startswith(p) for p in rules.medium_write_action_provider_prefixes):
        last = _azure_last_segment(permission)
        if last in ("write", "action"):
            if any(k in lower for k in ("roleassignments", "roledefinitions", "authorization")):
                return None
            return "medium"

    if rules.resourcehealth_events_action_prefix and lower.startswith(rules.resourcehealth_events_action_prefix) and lower.endswith("/action"):
        return "medium"

    if rules.billing_provider_prefix and lower.startswith(rules.billing_provider_prefix):
        if any(k in lower for k in rules.billing_exclude_keywords):
            return None
        last = _azure_last_segment(permission)
        if last in ("write", "action"):
            return "medium"

    if rules.appinsights_component_prefix and lower.startswith(rules.appinsights_component_prefix):
        if any(k in lower for k in rules.appinsights_exclude_keywords):
            return None
        last = _azure_last_segment(permission)
        if last in ("write", "action"):
            return "medium"

    return None


def _azure_graph_or_synthetic_level(permission: str) -> Optional[str]:
    """Classify non-ARM evidence produced by AzurePEASS."""

    lower = permission.strip().lower()
    if not lower:
        return None

    if lower.startswith("az-cli/read/"):
        # The probe suppresses command output and only records that an
        # argument-free read command succeeded. Credential-returning command
        # names remain critical even though current az help normally requires
        # a resource argument and skips them.
        if re.search(
            r"/(?:list|get|show|generate|retrieve|regenerate)[^/]*"
            r"(?:secret|credential|password|token|keys?)(?:/|$)",
            lower,
        ):
            return "critical"
        return "low"

    if lower.startswith("owner of "):
        if any(
            marker in lower
            for marker in ("application", "serviceprincipal", "managedidentity")
        ):
            return "critical"
        if "group" in lower:
            return "high"
        return "medium"

    if lower.startswith("entra.directoryrole/"):
        # The role definition could not be resolved. Do not pretend an unknown
        # Entra directory role is ordinary metadata access.
        return "medium"

    if lower.startswith("microsoft.directory/"):
        if lower in _ENTRA_MEDIUM_EXACT:
            return "medium"
        last = lower.rsplit("/", 1)[-1]
        if any(
            marker in lower
            for marker in (
                "/applications/credentials/",
                "/applications/owners/update",
                "/applications/allproperties/alltasks",
                "/serviceprincipals/credentials/",
                "/serviceprincipals/owners/update",
                "/serviceprincipals/allproperties/alltasks",
                "/groups/members/update",
                "/groups/owners/update",
                "/groups/allproperties/alltasks",
                "/oauth2permissiongrants/",
                "/roleassignments/",
                "/roledefinitions/",
                "/directoryroles/allproperties/alltasks",
                "/users/password/update",
                "/users/allproperties/alltasks",
                "/conditionalaccesspolicies/allproperties/alltasks",
                "/managepermissiongrantsforall",
            )
        ):
            return "critical"
        if "/credentials/" in lower and last in {"create", "manage", "update"}:
            return "critical"
        if "/users/authenticationmethods/" in lower:
            return "medium" if last == "read" else "critical"
        if "/groupsassignabletoroles/" in lower:
            if any(marker in lower for marker in ("/members/update", "/owners/update")):
                return "critical"
            if last == "read":
                return "low"
            if last in {
                "assignlicense",
                "create",
                "delete",
                "reprocesslicenseassignment",
                "restore",
                "update",
            }:
                return "medium"
            return "high"
        if any(
            marker in lower
            for marker in (
                "/bitlockerkeys/key/read",
                "/devicelocalcredentials/password/read",
                "getpasswordsinglesignoncredentials",
                "managepasswordsinglesignoncredentials",
            )
        ):
            return "critical"
        if last == "read" and any(
            marker in lower
            for marker in (
                "/auditlogs/",
                "/groups/allproperties/",
                "/privilegedidentitymanagement/",
                "/provisioninglogs/",
                "/signinreports/",
                "/users/allproperties/",
            )
        ):
            return "high"
        if last == "alltasks":
            return "high"
        if any(
            marker in lower
            for marker in (
                "/approleassignedto/",
                "/authentication/",
                "/authorizationpolicy/",
                "/crosstenantaccesspolicy/",
                "/deviceregistrationpolicy/",
                "/domains/federationconfiguration/",
                "/hybridauthenticationpolicy/",
                "/namedlocations/",
                "/owners/",
                "/passwordhashsync/",
                "/permissiongrantpolicies/",
                "/permissions/",
                "/serviceprincipalcreationpolicies/",
            )
        ) and last in {
            "create",
            "delete",
            "disable",
            "enable",
            "manage",
            "restore",
            "update",
        }:
            return "high"
        if last == "read":
            return "low"
        return "medium"

    if lower.startswith("microsoft.") and lower.endswith("/alltasks"):
        return "high"

    if lower.startswith("microsoft.networkaccess/trafficlogs/") and lower.endswith(
        "/read"
    ):
        return "high"

    if lower.startswith(
        (
            "microsoft.azure.",
            "microsoft.office365.",
            "microsoft.teams/",
        )
    ):
        last = lower.rsplit("/", 1)[-1]
        if last == "alltasks":
            return "high"
        if last == "read":
            return "low"
        return "medium"

    # OAuth scopes/app roles use dotted names and no ARM-style slash.
    if "/" not in lower and ("." in lower or lower in _GRAPH_LOW_EXACT):
        if lower in _GRAPH_CRITICAL_EXACT:
            return "critical"
        if lower in _GRAPH_HIGH_EXACT:
            return "high"
        if lower in _GRAPH_MEDIUM_EXACT:
            return "medium"
        if lower in _GRAPH_LOW_EXACT:
            return "low"
        credential_markers = (
            "authenticationmethod",
            "bitlockerkey",
            "credential",
            "devicelocalcredential",
            "password",
        )
        if any(marker in lower for marker in credential_markers):
            if any(
                operation in lower
                for operation in ("readwrite", "write", "manage")
            ):
                return "critical"
            if ".read" in lower:
                return "high"
        # Unknown Graph writes are operationally interesting, but are not
        # promoted without a concrete escalation or sensitive-data path.
        # Known high-impact scopes and sensitive workload families are handled
        # above and below respectively.
        if lower.endswith(".read.all"):
            return "medium"
        if lower.endswith(".readbasic.all"):
            return "medium"
        if any(lower.startswith(prefix) for prefix in _GRAPH_SENSITIVE_DATA_PREFIXES):
            if any(
                operation in lower
                for operation in (
                    ".read",
                    ".write",
                    ".manage",
                    ".fullcontrol",
                    ".send",
                    ".create",
                )
            ):
                return "high"
        if lower.endswith(".read"):
            return "low"
        return "medium"

    return None


def _azure_wildcard_level(permission: str, rules: AzureRules) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    # True full-admin wildcards remain critical.
    if permission == "*" or permission == "*/*":
        return "critical"

    lower = permission.lower()
    if lower == "*/read":
        return "medium"
    if lower in {"*/write", "*/action"}:
        return "critical"
    if lower == "*/delete":
        return "medium"

    if "*" in lower and lower.endswith("/read"):
        if lower.startswith("microsoft.storage/") and (
            lower.startswith("microsoft.storage/*/")
            or any(
                marker in lower
                for marker in (
                    "/blobservices/",
                    "/fileservices/",
                    "/queueservices/",
                    "/tableservices/",
                )
            )
        ):
            return "high"
        if lower.startswith("microsoft.machinelearningservices/") and any(
            marker in lower for marker in ("/data/", "/datasets/")
        ):
            return "high"
        return "medium"
    if "*" in lower and lower.endswith("/delete"):
        return "medium"
    if "*" in lower and lower.endswith(("/write", "/action")):
        static_base = lower.split("*", 1)[0].rstrip("/")
        if static_base in _AZURE_CRITICAL_WILDCARD_BASES:
            return "critical"
        return "high"

    if not permission.endswith("/*"):
        return None

    base = permission[:-2].strip("/")
    lower_base = base.lower()

    if lower_base.count("/") == 0:
        if lower_base in _AZURE_CRITICAL_PROVIDER_ROOTS:
            return "critical"
        if lower_base in _AZURE_HIGH_PROVIDER_ROOTS:
            return "high"
        return "medium"

    if lower_base in _AZURE_CRITICAL_WILDCARD_BASES:
        return "critical"

    if lower_base.startswith("microsoft.storage/storageaccounts/") and any(
        marker in lower_base
        for marker in ("/blobservices", "/fileservices", "/queueservices", "/tableservices")
    ):
        return "high"

    if lower_base.startswith("microsoft.machinelearningservices/") and any(
        marker in lower_base for marker in ("/data", "/datasets")
    ):
        return "high"

    likely_child_permissions = [f"{base}/{verb}" for verb in ("read", "write", "delete", "action")]
    return _highest_risk(_azure_classify_non_wildcard(child, rules) for child in likely_child_permissions)


def _azure_classify_non_wildcard(permission: str, rules: AzureRules) -> Optional[str]:
    lower = permission.lower()

    if lower in _AZURE_CRITICAL_EXACT:
        return "critical"
    if lower in _AZURE_HIGH_EXACT:
        return "high"
    if lower in _AZURE_MEDIUM_EXACT:
        return "medium"
    if lower.endswith("/readmetadata/action"):
        return "medium"

    forced = azure_override_level(permission, rules)
    if forced is not None:
        return forced

    last = _azure_last_segment(permission)
    is_read = last == "read"
    is_write = last == "write"
    is_delete = last == "delete"
    is_action = last == "action"

    credential_like_action = re.search(
        r"/(?:list|get|generate|retrieve|regenerate)[^/]*"
        r"(?:secret|credential|password|token|connectionstrings?|sas|adminkeys?|authkeys?|accesskeys?|keys?)"
        r"/action$",
        lower,
    )
    if rules.credential_action_re.search(lower) or credential_like_action:
        # Operation names are not impact evidence. Known reusable credential
        # paths are promoted by the exact sets or configured attack
        # combinations; an otherwise unknown provider action stays Medium
        # until its returned material is proven usable.
        return "medium"

    if lower.startswith("microsoft.authorization/"):
        if lower.endswith("/roleassignments/write"):
            return "critical"
        if lower.endswith("/elevateaccess/action"):
            return "critical"

    # Only actual Storage objects and access-control/superuser operations expose
    # data. Service/container/share metadata remains ordinary control-plane IO.
    if lower.startswith("microsoft.storage/") and any(
        x in lower for x in ("/blobservices/", "/fileservices/", "/queueservices/", "/tableservices/")
    ):
        if "/providers/microsoft.insights/" in lower:
            if is_read:
                return "low"
            if is_write or is_action:
                return "medium"
        if lower.endswith("/usages/read"):
            return "low"
        data_markers = (
            "/containers/blobs/",
            "/fileshares/files/",
            "/queues/messages/",
            "/tables/entities/",
        )
        access_markers = (
            "/getacl/action",
            "/setacl/action",
            "/takeownership/action",
            "/actassuperuser/action",
            "/runassuperuser/action",
            "/modifypermissions/action",
            "/bypasspermissions/action",
            "/runasbuiltinfileadministrator/action",
        )
        if any(marker in lower for marker in data_markers + access_markers):
            if is_delete or "/delete" in lower:
                return "medium"
            if is_read or is_write or is_action:
                return "high"

    # Machine Learning data and dataset operations can expose or poison model
    # inputs even though they use ARM-shaped operation names.
    if lower.startswith("microsoft.machinelearningservices/") and any(
        marker in lower for marker in ("/data/", "/datasets/")
    ):
        if is_delete or "/delete" in lower:
            return "medium"
        if is_read or is_write or is_action:
            return "high"

    if is_delete or "/delete" in lower:
        return "medium"

    if is_read:
        return "low"

    if is_write or is_action:
        if "/roleassignments/" in lower:
            return "critical"
        if "managedidentity" in lower and (
            lower.endswith("/assign/action")
            or "/federatedidentitycredentials/" in lower
        ):
            return "critical"
        if "/rbac.authorization.k8s.io/" in lower:
            return "high"
        if is_write and any(
            marker in lower for marker in ("/secrets/", "/keys/", "/certificates/")
        ):
            return "high"
        if is_action and (
            ("/secrets/" in lower and any(word in lower for word in ("/peek/", "/setsecret/")))
            or (
                any(marker in lower for marker in ("/keys/", "/certificates/"))
                and any(word in lower for word in ("/create/", "/import/", "/release/"))
            )
        ):
            return "high"
        return "medium"

    return None


def azure_regex_classify(permission: str, rules: AzureRules) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    non_arm_level = _azure_graph_or_synthetic_level(permission)
    if non_arm_level is not None:
        return non_arm_level

    wildcard_level = _azure_wildcard_level(permission, rules)
    if wildcard_level is not None:
        return wildcard_level

    return _azure_classify_non_wildcard(permission, rules)


def classify_permission(provider: str, permission: str, *, unknown_default: str = "high") -> str:
    """
    Classify a single permission by risk level.
    
    Args:
        provider: Cloud provider ("aws", "gcp", "azure")
        permission: Permission string to classify
        unknown_default: Risk level for permissions that don't match any rule
    
    Returns:
        Risk level: "low", "medium", "high", or "critical"
    """
    provider = provider.lower().strip()
    permission = (permission or "").strip()
    if unknown_default not in RISK_LEVELS:
        raise ValueError(f"unknown_default must be one of {RISK_LEVELS}")
    if not permission:
        return unknown_default

    if provider == "aws":
        category = aws_regex_classify(permission, load_rules("aws"))
    elif provider == "gcp":
        category = gcp_regex_classify(permission, load_rules("gcp"))
    elif provider == "azure":
        category = azure_regex_classify(permission, load_rules("azure"))
    else:
        raise ValueError(f"Unknown provider: {provider}")

    return category or unknown_default


def classify_all(
    provider: str,
    permissions: Iterable[str],
    unknown_default: str = "high",
) -> dict[str, list[str]]:
    """
    Classify multiple permissions by risk level.
    
    Args:
        provider: Cloud provider ("aws", "gcp", "azure")
        permissions: Iterable of permission strings to classify
        unknown_default: Risk level for permissions that don't match any rule
    
    Returns:
        Dictionary mapping risk levels to lists of permissions
    """
    categories: dict[str, list[str]] = {"low": [], "medium": [], "high": [], "critical": []}
    seen: set[str] = set()

    for perm in permissions:
        if not isinstance(perm, str):
            continue
        perm = perm.strip()
        if not perm or perm in seen:
            continue
        seen.add(perm)

        category = classify_permission(provider, perm, unknown_default=unknown_default)
        categories[category].append(perm)

    return categories
