"""
Permission risk classifier for AWS, Azure, and GCP.
Adapted from Blue-PEASS for CloudPEASS integration.
Downloads risk_rules YAML files from Blue-PEASS repo at runtime.

Note: The Blue-PEASS repository must be publicly accessible at:
https://github.com/carlospolop/Blue-PEASS
"""

from __future__ import annotations

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

# Blue-PEASS GitHub repository base URL
# Note: Update this to match your Blue-PEASS repository name and branch
BLUEPEASS_RISK_RULES_BASE_URL = "https://raw.githubusercontent.com/carlospolop/Blue-PEASS/main/risk_rules"
RISK_RULES_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


def _cache_dir() -> Path:
    """Get cache directory for risk rules."""
    return Path.home() / ".cache" / "cloudpeass" / "risk_rules"


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
    """Load YAML rules from cache or download from Blue-PEASS."""
    cache_path = _cache_dir() / f"{provider}.yaml"
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    yaml_text = None
    
    # Download if cache is stale
    if _should_refresh_cache(cache_path):
        yaml_text = _download_risk_rules(provider)
        if yaml_text:
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

    if not yaml_text:
        return {}

    try:
        data = yaml.safe_load(yaml_text) or {}
    except Exception as e:
        print(f"Warning: Couldn't parse risk rules YAML for {provider}: {e}")
        return {}

    if not isinstance(data, dict):
        return {}
    
    return data


@dataclass(frozen=True)
class AwsRules:
    critical_exact: set[str]
    low_exact: set[str]
    high_exact: set[str]
    critical_exact_lower: set[str]
    low_exact_lower: set[str]
    high_exact_lower: set[str]
    benign_write_medium_action_re: tuple[re.Pattern[str], ...]
    write_like_prefix_re: re.Pattern[str]
    dangerous_write_re: re.Pattern[str]
    sensitive_read_substrings: tuple[str, ...]
    sensitive_read_substrings_lower: tuple[str, ...]
    iam_critical_verbs: set[str]
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
        sensitive_read_substrings = tuple(data.get("sensitive_read_substrings") or [])
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
            critical_exact_lower={x.lower() for x in critical_exact},
            low_exact_lower={x.lower() for x in low_exact},
            high_exact_lower={x.lower() for x in high_exact},
            benign_write_medium_action_re=tuple(
                re.compile(p, re.IGNORECASE) for p in (data.get("benign_write_medium_action_regex") or [])
            ),
            write_like_prefix_re=re.compile(write_like_prefix_regex, re.IGNORECASE),
            dangerous_write_re=re.compile(dangerous_write_regex, re.IGNORECASE),
            sensitive_read_substrings=sensitive_read_substrings,
            sensitive_read_substrings_lower=tuple(s.lower() for s in sensitive_read_substrings),
            iam_critical_verbs=set(data.get("iam_critical_verbs") or []),
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
            critical_suffixes=tuple(data.get("critical_suffixes") or []),
            critical_exact=set(data.get("critical_exact") or []),
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


def aws_override_level(action: str, rules: AwsRules) -> Optional[str]:
    action = action.strip()
    if not action:
        return None

    action_lower = action.lower()

    if action_lower in rules.low_exact_lower:
        return "low"
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


def aws_regex_classify(action: str, rules: AwsRules) -> Optional[str]:
    action = action.strip()
    if not action:
        return None

    if action == "*" or action.endswith(":*"):
        return "critical"

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
        if verb in rules.iam_critical_verbs or verb_lower == "passrole":
            return "critical"
        return "high"

    if service == "sts" and verb_lower.startswith("assumerole"):
        return "critical"

    if verb_lower in rules.resource_policy_verbs_lower or (
        verb_lower.endswith(rules.resource_policy_suffixes_lower) and verb_lower.startswith(rules.resource_policy_prefixes_lower)
    ):
        return "critical"

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
        return "high"

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
    if permission in rules.low_exact:
        return "low"
    if permission in rules.critical_exact:
        return "critical"

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

        if lower.startswith(rules.insights_activitylogalerts_prefix) and (lower.endswith("/write") or lower.endswith("/activated/action")):
            return "medium"

        if lower.startswith(rules.insights_alertrules_prefix) and lower.endswith(
            ("/write", "/activated/action", "/resolved/action", "/throttled/action")
        ):
            return "medium"

    if any(lower.startswith(p) for p in rules.medium_write_action_provider_prefixes):
        last = _azure_last_segment(permission)
        if last in ("write", "action"):
            if any(k in lower for k in ("roleassignments", "roledefinitions", "authorization")):
                return None
            return "medium"

    if lower.startswith(rules.resourcehealth_events_action_prefix) and lower.endswith("/action"):
        return "medium"

    if lower.startswith(rules.billing_provider_prefix):
        if any(k in lower for k in rules.billing_exclude_keywords):
            return None
        last = _azure_last_segment(permission)
        if last in ("write", "action"):
            return "medium"

    if lower.startswith(rules.appinsights_component_prefix):
        if any(k in lower for k in rules.appinsights_exclude_keywords):
            return None
        last = _azure_last_segment(permission)
        if last in ("write", "action"):
            return "medium"

    return None


def azure_regex_classify(permission: str, rules: AzureRules) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    forced = azure_override_level(permission, rules)
    if forced is not None:
        return forced

    lower = permission.lower()

    if permission == "*" or permission.endswith("/*") or permission == "*/*":
        return "critical"

    last = _azure_last_segment(permission)
    is_read = last == "read"
    is_write = last == "write"
    is_delete = last == "delete"
    is_action = last == "action"

    if lower.startswith("microsoft.authorization/"):
        if lower.endswith("/roleassignments/write") or lower.endswith("/roledefinitions/write"):
            return "critical"
        if lower.endswith("/elevateaccess/action"):
            return "critical"

    # Storage data-plane: blob/file/queue/table reads/writes -> high; deletes -> medium.
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
        if is_delete or "/delete" in lower:
            return "medium"
        if is_read or is_write or is_action:
            return "high"

    if is_delete or "/delete" in lower:
        return "medium"

    if rules.credential_action_re.search(lower):
        return "medium" if is_delete else "critical"

    if lower.startswith("microsoft.keyvault/") and any(x in lower for x in ("/secrets/", "/keys/", "/certificates/")):
        if is_read:
            return "critical"

    if is_read:
        return "low"

    if is_write or is_action:
        if "/roleassignments/" in lower or "/roledefinitions/" in lower:
            return "critical"
        if "managedidentity" in lower and ("assign" in lower or "federatedidentitycredentials" in lower):
            return "critical"
        if any(k in lower for k in rules.dangerous_write_keywords_lower):
            return "high"
        return "medium"

    return None


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
