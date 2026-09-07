"""Read-only Kubernetes permission enumeration and risk explanation."""

from __future__ import annotations

import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from colorama import Back, Fore, Style, init

from src.CloudPEASS.interactive import confirm_slow_operation

from .client import APIError, K8sClient
from .discovery import discover_api_resources
from .models import APIResource, Coverage, PermissionFinding, PermissionKey
from .passive import (
    analyze_admission_read_only,
    discover_namespaces,
    is_valid_namespace_name,
)
from .rbac import collect_rbac_explanations
from .reviews import (
    decode_jwt_without_verification,
    findings_from_rules,
    get_identity,
    self_subject_access_review,
    self_subject_rules_review,
)
from .risks import classify_permission


init(autoreset=True)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class K8sPEASS:
    """Kubernetes PEASS with the same high-level flow as the cloud PEASS tools."""

    def __init__(
        self,
        *,
        kubeconfig: str | None = None,
        context: str | None = None,
        server: str | None = None,
        token: str | None = None,
        certificate_authority: str | None = None,
        client_certificate: str | None = None,
        client_key: str | None = None,
        impersonate_user: str | None = None,
        impersonate_groups: list[str] | None = None,
        insecure_skip_tls_verify: bool = False,
        namespaces: list[str] | None = None,
        threads: int = 5,
        timeout: int = 15,
        retries: int = 2,
        brute_force_permissions: bool = False,
        skip_bruteforce: bool = False,
        no_ask: bool = False,
        show_all: bool = False,
        out_path: str | None = None,
    ) -> None:
        self.client = K8sClient(
            kubeconfig=kubeconfig,
            context=context,
            server=server,
            token=token,
            certificate_authority=certificate_authority,
            client_certificate=client_certificate,
            client_key=client_key,
            impersonate_user=impersonate_user,
            impersonate_groups=impersonate_groups,
            insecure_skip_tls_verify=insecure_skip_tls_verify,
            timeout=timeout,
            retries=retries,
        )
        self.explicit_token = token
        self.requested_namespaces = namespaces or []
        self.threads = max(1, min(int(threads), 20))
        self.brute_force_permissions = brute_force_permissions
        self.skip_bruteforce = skip_bruteforce
        self.no_ask = no_ask
        self.show_all = show_all
        self.out_path = out_path
        self.coverage = Coverage()

    def close(self) -> None:
        self.client.close()

    def run_analysis(self) -> dict[str, Any]:
        print(f"{Fore.GREEN}\nStarting CloudPEASS analysis for Kubernetes...")
        print(
            f"{Fore.YELLOW}[{Fore.BLUE}i{Fore.YELLOW}] Strict read-only mode: "
            "no workload writes, exec, attach, proxy use, token minting, or dry-run writes."
        )

        context_info = self.client.context_info()
        local_token = self.client.local_bearer_token()
        identity, identity_method, identity_warnings = get_identity(
            self.client, local_token
        )
        self.coverage.identity_method = identity_method
        self.coverage.warnings.extend(identity_warnings)
        self._print_identity(context_info, identity)

        server_version = self._server_version()
        resources, discovery_warnings = discover_api_resources(self.client)
        self.coverage.discovery_complete = not discovery_warnings and bool(resources)
        self.coverage.warnings.extend(discovery_warnings)
        print(
            f"{Fore.MAGENTA}\nDiscovered {len(resources)} API resources/subresources "
            f"using {self.client.backend}."
        )

        namespace_candidates = list(self.requested_namespaces)
        namespace_candidates.append(str(context_info.get("namespace") or "default"))
        token_claims = decode_jwt_without_verification(local_token)
        kubernetes_claims = token_claims.get("kubernetes.io") or {}
        token_namespace = str(kubernetes_claims.get("namespace") or "")
        if token_namespace:
            namespace_candidates.append(token_namespace)
            if is_valid_namespace_name(token_namespace):
                self.coverage.namespace_sources["token-claim-unverified"] = [
                    token_namespace
                ]
        initial_namespaces: list[str] = []
        for namespace in namespace_candidates:
            if is_valid_namespace_name(namespace):
                initial_namespaces.append(namespace)
            elif namespace:
                self.coverage.warnings.append(
                    f"Ignored invalid namespace name from local input: {namespace!r}"
                )
        namespaces, namespace_objects, namespace_error = discover_namespaces(
            self.client, initial_namespaces
        )
        self.coverage.namespace_sources["local-or-user-supplied"] = sorted(
            set(initial_namespaces)
        )
        if namespace_objects:
            listed = sorted(
                {
                    str((item.get("metadata") or {}).get("name"))
                    for item in namespace_objects
                    if (item.get("metadata") or {}).get("name")
                }
            )
            if namespace_error:
                self.coverage.namespace_sources["namespace-exact-get"] = listed
                self.coverage.hidden_namespaces_possible = True
                self.coverage.unavailable_inventories.append(
                    f"namespace list: {namespace_error}"
                )
            else:
                self.coverage.namespace_sources["namespace-list"] = listed
                self.coverage.hidden_namespaces_possible = False
                self.coverage.readable_inventories.append("namespaces")
        else:
            self.coverage.hidden_namespaces_possible = True
            if namespace_error:
                self.coverage.unavailable_inventories.append(
                    f"namespaces: {namespace_error}"
                )

        summarized: list[PermissionFinding] = []
        for namespace in namespaces:
            status, error = self_subject_rules_review(self.client, namespace)
            if error:
                self.coverage.rules_reviews_complete = False
                self.coverage.rules_review_errors.append(f"{namespace}: {error}")
                continue
            if status.get("incomplete"):
                self.coverage.rules_reviews_complete = False
                detail = str(status.get("evaluationError") or "server marked incomplete")
                self.coverage.rules_review_errors.append(f"{namespace}: {detail}")
            summarized.extend(findings_from_rules(status, namespace))

        summarized = self._normalize_summarized_findings(summarized, resources)
        confirmed = self._confirm_high_risk(summarized)
        if not summarized:
            confirmed.extend(self._fallback_checks(namespaces, resources))

        exhaustive = self._maybe_run_exhaustive(resources, namespaces)
        all_findings = self._merge_findings(summarized + confirmed + exhaustive)

        admission, readable, unavailable = analyze_admission_read_only(
            self.client, namespace_objects, namespaces, resources
        )
        all_findings = self._annotate_admission(all_findings, admission)
        self.coverage.readable_inventories.extend(readable)
        self.coverage.unavailable_inventories.extend(unavailable)
        rbac_explanations, readable, unavailable = collect_rbac_explanations(
            self.client, identity, namespaces
        )
        self.coverage.readable_inventories.extend(readable)
        self.coverage.unavailable_inventories.extend(unavailable)

        report = {
            "tool": "K8sPEASS",
            "read_only": True,
            "guardrails": {
                "resource_writes": "never",
                "exec_attach_portforward_proxy": "never",
                "admission_write_probes": "never",
                "permitted_posts": [
                    "SelfSubjectReview",
                    "SelfSubjectRulesReview",
                    "SelfSubjectAccessReview",
                ],
            },
            "context": context_info,
            "server_version": server_version,
            "principal": identity,
            "coverage": self.coverage.to_dict(),
            "api_resource_count": len(resources),
            "api_resources": [asdict(item) for item in resources],
            "namespaces": namespaces,
            "permissions": [finding.to_dict() for finding in all_findings],
            "rbac_explanations": rbac_explanations,
            "admission_configuration": admission,
        }
        self._print_report(all_findings, admission)
        if self.out_path:
            self._write_json(report)
        return report

    def _server_version(self) -> dict[str, Any]:
        try:
            return self.client.get("/version")
        except APIError as exc:
            self.coverage.warnings.append(f"Server version unavailable: {exc}")
            return {}

    def _print_identity(
        self, context_info: dict[str, Any], identity: dict[str, Any]
    ) -> None:
        print(f"{Fore.MAGENTA}\nGetting information about your principal...")
        print(f"{Fore.WHITE}Context: {Fore.CYAN}{context_info.get('context') or 'unknown'}")
        print(f"{Fore.WHITE}Server:  {Fore.CYAN}{context_info.get('server') or 'unknown'}")
        print(f"{Fore.WHITE}User:    {Fore.CYAN}{identity.get('username') or 'unknown'}")
        groups = identity.get("groups") or []
        print(f"{Fore.WHITE}Groups:  {Fore.CYAN}{', '.join(groups) or 'unknown'}")

    def _normalize_summarized_findings(
        self,
        findings: list[PermissionFinding],
        resources: list[APIResource],
    ) -> list[PermissionFinding]:
        by_name: dict[tuple[str, str, str], list[APIResource]] = {}
        for item in resources:
            lookup_key = (item.group, item.resource, item.subresource)
            by_name.setdefault(lookup_key, []).append(item)

        normalized: list[PermissionFinding] = []
        for finding in findings:
            key = finding.key
            matches = by_name.get((key.group, key.resource, key.subresource), [])
            if matches:
                selected = matches[0]
                new_key = replace(
                    key,
                    version=selected.version,
                    namespace=key.namespace if selected.namespaced else "",
                )
                severity, explanation = classify_permission(new_key)
                finding = replace(
                    finding,
                    key=new_key,
                    severity=severity,
                    explanation=explanation,
                )
            normalized.append(finding)
        return normalized

    def _confirm_high_risk(
        self, summarized: list[PermissionFinding], limit: int = 75
    ) -> list[PermissionFinding]:
        candidates: list[PermissionKey] = []
        seen: set[PermissionKey] = set()
        for finding in summarized:
            if finding.severity not in {"critical", "high"}:
                continue
            if finding.key in seen:
                continue
            seen.add(finding.key)
            candidates.append(finding.key)
        if len(candidates) > limit:
            self.coverage.warnings.append(
                f"Confirmed the first {limit} high-risk summarized permissions. "
                "Use --brute-force-permissions for exhaustive exact checks."
            )
            candidates = candidates[:limit]
        return self._run_access_reviews(candidates)

    def _fallback_checks(
        self,
        namespaces: list[str],
        resources: list[APIResource],
    ) -> list[PermissionFinding]:
        """Small fixed SSAR set used when rules summaries reveal nothing."""
        del resources
        candidates: list[PermissionKey] = []
        for namespace in (namespaces[:5] or ["default"]):
            candidates.extend(
                [
                    PermissionKey("get", resource="secrets", namespace=namespace),
                    PermissionKey("list", resource="secrets", namespace=namespace),
                    PermissionKey("create", resource="pods", namespace=namespace),
                    PermissionKey(
                        "create",
                        resource="pods",
                        subresource="exec",
                        namespace=namespace,
                    ),
                    PermissionKey(
                        "create",
                        resource="serviceaccounts",
                        subresource="token",
                        namespace=namespace,
                    ),
                    PermissionKey(
                        "patch",
                        group="apps",
                        version="v1",
                        resource="deployments",
                        namespace=namespace,
                    ),
                    PermissionKey(
                        "create",
                        group="rbac.authorization.k8s.io",
                        version="v1",
                        resource="rolebindings",
                        namespace=namespace,
                    ),
                ]
            )
        candidates.extend(
            [
                PermissionKey("get", resource="nodes", subresource="proxy"),
                PermissionKey(
                    "create",
                    group="rbac.authorization.k8s.io",
                    version="v1",
                    resource="clusterrolebindings",
                ),
                PermissionKey(
                    "impersonate",
                    group="authentication.k8s.io",
                    version="v1",
                    resource="users",
                ),
                PermissionKey("get", non_resource_url="/metrics"),
                PermissionKey("get", non_resource_url="/debug/pprof/"),
            ]
        )
        return self._run_access_reviews(candidates)

    def _maybe_run_exhaustive(
        self,
        resources: list[APIResource],
        namespaces: list[str],
    ) -> list[PermissionFinding]:
        if self.skip_bruteforce:
            self.coverage.brute_force_skipped_reason = "disabled by --skip-bruteforce"
            return []
        candidates = self._exhaustive_candidates(resources, namespaces)
        description = (
            f"Run {len(candidates)} additional non-persisted authorization reviews? "
            "This is slow and creates audit-log noise"
        )
        should_run = confirm_slow_operation(
            description,
            force=self.brute_force_permissions,
            no_ask=self.no_ask,
        )
        if not should_run:
            self.coverage.brute_force_skipped_reason = (
                "not explicitly approved; use --brute-force-permissions to bypass the prompt"
            )
            return []
        self.coverage.brute_force_run = True
        print(
            f"{Fore.MAGENTA}\nRunning {len(candidates)} exact authorization reviews..."
        )
        return self._run_access_reviews(candidates)

    @staticmethod
    def _exhaustive_candidates(
        resources: list[APIResource],
        namespaces: list[str],
    ) -> list[PermissionKey]:
        candidates: set[PermissionKey] = set()
        for item in resources:
            scopes = namespaces if item.namespaced else [""]
            for namespace in scopes:
                for verb in item.verbs:
                    candidates.add(
                        PermissionKey(
                            verb=verb,
                            group=item.group,
                            version=item.version,
                            resource=item.resource,
                            subresource=item.subresource,
                            namespace=namespace,
                        )
                    )
        candidates.update(
            {
                PermissionKey(
                    verb="escalate",
                    group="rbac.authorization.k8s.io",
                    version="v1",
                    resource="clusterroles",
                ),
                PermissionKey(
                    verb="bind",
                    group="rbac.authorization.k8s.io",
                    version="v1",
                    resource="clusterroles",
                ),
                PermissionKey(
                    verb="impersonate",
                    group="authentication.k8s.io",
                    version="v1",
                    resource="users",
                ),
                PermissionKey(
                    verb="impersonate",
                    group="authentication.k8s.io",
                    version="v1",
                    resource="groups",
                ),
                PermissionKey(
                    verb="impersonate",
                    group="authentication.k8s.io",
                    version="v1",
                    resource="uids",
                ),
                PermissionKey(
                    verb="impersonate",
                    group="authentication.k8s.io",
                    version="v1",
                    resource="userextras",
                ),
                PermissionKey(
                    verb="approve",
                    group="certificates.k8s.io",
                    version="v1",
                    resource="signers",
                ),
                PermissionKey(
                    verb="sign",
                    group="certificates.k8s.io",
                    version="v1",
                    resource="signers",
                ),
                PermissionKey(
                    verb="attest",
                    group="certificates.k8s.io",
                    version="v1",
                    resource="signers",
                ),
            }
        )
        for namespace in namespaces:
            candidates.update(
                {
                    PermissionKey(
                        verb="escalate",
                        group="rbac.authorization.k8s.io",
                        version="v1",
                        resource="roles",
                        namespace=namespace,
                    ),
                    PermissionKey(
                        verb="bind",
                        group="rbac.authorization.k8s.io",
                        version="v1",
                        resource="roles",
                        namespace=namespace,
                    ),
                    PermissionKey(
                        verb="impersonate",
                        group="",
                        version="v1",
                        resource="serviceaccounts",
                        namespace=namespace,
                    ),
                }
            )
        for path in (
            "/api",
            "/apis",
            "/version",
            "/healthz",
            "/livez",
            "/readyz",
            "/metrics",
            "/logs",
            "/debug/pprof/",
            "/openapi/v2",
        ):
            for verb in ("get", "post", "put", "patch", "delete"):
                candidates.add(PermissionKey(verb, non_resource_url=path))
        return sorted(candidates, key=lambda key: key.human())

    def _run_access_reviews(
        self, candidates: list[PermissionKey]
    ) -> list[PermissionFinding]:
        if not candidates:
            return []
        results: list[PermissionFinding] = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(self_subject_access_review, self.client, key): key
                for key in candidates
            }
            for future in as_completed(future_map):
                key = future_map[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    severity, explanation = classify_permission(key)
                    results.append(
                        PermissionFinding(
                            key=key,
                            allowed=False,
                            reason=str(exc),
                            evaluation_error=str(exc),
                            confidence="unknown",
                            severity=severity,
                            explanation=explanation,
                        )
                    )
        self.coverage.exact_checks += len(results)
        return results

    @staticmethod
    def _merge_findings(
        findings: list[PermissionFinding],
    ) -> list[PermissionFinding]:
        confidence_rank = {"confirmed": 3, "summarized": 2, "incomplete": 1, "unknown": 0}
        merged: dict[PermissionKey, PermissionFinding] = {}
        for finding in findings:
            current = merged.get(finding.key)
            if current is None:
                merged[finding.key] = finding
                continue
            if current.allowed and not finding.allowed and not finding.denied:
                continue
            if confidence_rank.get(finding.confidence, 0) >= confidence_rank.get(
                current.confidence, 0
            ):
                merged[finding.key] = finding
        return sorted(
            merged.values(),
            key=lambda finding: (
                not finding.allowed,
                SEVERITY_ORDER.get(finding.severity, 9),
                finding.key.human(),
            ),
        )

    @staticmethod
    def _annotate_admission(
        findings: list[PermissionFinding],
        admission: list[dict[str, Any]],
    ) -> list[PermissionFinding]:
        psa_namespaces = {
            str(item.get("name") or ""): item.get("configuration") or {}
            for item in admission
            if item.get("type") == "Pod Security Admission namespace labels"
        }
        write_verbs = {"create", "update", "patch", "delete", "deletecollection", "*"}
        annotated: list[PermissionFinding] = []
        for finding in findings:
            if not finding.allowed or finding.key.verb.lower() not in write_verbs:
                annotated.append(finding)
                continue
            note = (
                "Authorization allows this operation, but mutating/validating admission "
                "may modify or reject it; K8sPEASS did not send a write probe."
            )
            labels = psa_namespaces.get(finding.key.namespace)
            if labels and finding.key.resource in {
                "pods",
                "deployments",
                "daemonsets",
                "statefulsets",
                "replicasets",
                "replicationcontrollers",
                "jobs",
                "cronjobs",
            }:
                note += f" Pod Security Admission labels observed: {labels}."
            annotated.append(replace(finding, admission=note))
        return annotated

    def _print_report(
        self,
        findings: list[PermissionFinding],
        admission: list[dict[str, Any]],
    ) -> None:
        allowed = [finding for finding in findings if finding.allowed]
        unknown = [finding for finding in findings if finding.confidence == "unknown"]
        counts = {
            severity: sum(1 for finding in allowed if finding.severity == severity)
            for severity in SEVERITY_ORDER
        }
        print(f"{Fore.YELLOW}\nPermission summary")
        print(
            f"{Fore.RED}{Back.YELLOW} Critical: {counts['critical']} {Style.RESET_ALL} "
            f"{Fore.RED}High: {counts['high']} {Fore.YELLOW}"
            f"Medium: {counts['medium']} {Fore.WHITE}Low: {counts['low']}"
        )
        print(
            f"{Fore.WHITE}Exact authorization reviews: "
            f"{Fore.CYAN}{self.coverage.exact_checks}"
        )

        for severity in ("critical", "high", "medium", "low"):
            items = [item for item in allowed if item.severity == severity]
            if not items or (severity == "low" and not self.show_all):
                continue
            color = {
                "critical": Fore.RED + Back.YELLOW,
                "high": Fore.RED,
                "medium": Fore.YELLOW,
                "low": Fore.WHITE,
            }[severity]
            print(f"\n{color}{severity.upper()} findings{Style.RESET_ALL}")
            display = items if self.show_all else items[:30]
            for finding in display:
                marker = "confirmed" if finding.confidence == "confirmed" else finding.confidence
                print(
                    f"  {color}[+] {finding.key.human()}{Style.RESET_ALL}\n"
                    f"      {finding.explanation} Evidence: {marker}."
                )
                if finding.reason:
                    print(f"      Authorization reason: {finding.reason}")
                if finding.admission != "not-applicable":
                    print(f"      Admission: {finding.admission}")
            if len(items) > len(display):
                print(
                    f"  ... {len(items) - len(display)} more; use --show-all or JSON output."
                )

        print(f"{Fore.YELLOW}\nAdmission visibility")
        if admission:
            print(
                f"  Read {len(admission)} admission or namespace-policy configurations. "
                "No admission write probes were performed."
            )
        else:
            print(
                "  No admission configuration was readable. Effective write admission "
                "behavior remains unknown because this tool never submits writes."
            )

        if unknown or self.coverage.warnings or self.coverage.unavailable_inventories:
            print(f"{Fore.YELLOW}\nCoverage limits")
            if self.coverage.hidden_namespaces_possible:
                print("  - Hidden namespace names may exist.")
            if self.coverage.brute_force_skipped_reason:
                print(f"  - Exhaustive checks: {self.coverage.brute_force_skipped_reason}.")
            for warning in self.coverage.warnings[:20]:
                print(f"  - {warning}")
            if self.coverage.unavailable_inventories:
                print(
                    f"  - {len(self.coverage.unavailable_inventories)} optional inventories "
                    "were not readable; see JSON for details."
                )

        completion = (
            "Analysis completed successfully"
            if self.coverage.discovery_complete
            else "Analysis completed with limited API visibility"
        )
        print(
            f"{Fore.GREEN}\n{completion}. "
            "No Kubernetes resources were changed and no exec-like action was used."
        )

    def _write_json(self, report: dict[str, Any]) -> None:
        target = Path(self.out_path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        )
        temporary = Path(handle.name)
        try:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            temporary.replace(target)
        finally:
            if not handle.closed:
                handle.close()
            temporary.unlink(missing_ok=True)
        print(f"{Fore.GREEN}Results saved to {target}")
