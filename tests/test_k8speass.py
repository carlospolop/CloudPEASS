import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.CloudPEASS.interactive import confirm_slow_operation
from src.k8s.client import APIError, K8sClient
from src.k8s.discovery import discover_api_resources
from src.k8s.k8speass import K8sPEASS
from src.k8s.models import APIResource, Coverage, PermissionFinding, PermissionKey
from src.k8s.passive import admission_sensitive_permissions, is_valid_namespace_name
from src.k8s.reviews import findings_from_rules
from src.k8s.risks import classify_permission


class ReadOnlyGuardrailTests(unittest.TestCase):
    def test_kubectl_allowlist_rejects_mutations_and_exec(self):
        for args in (
            ["apply", "-f", "pod.yaml"],
            ["delete", "pod", "x"],
            ["exec", "pod", "--", "id"],
            ["create", "--raw", "/api/v1/namespaces", "-f", "-"],
            ["get", "--raw", "/api/v1/nodes/node-1/proxy/metrics"],
            ["get", "--raw", "/api/v1/namespaces/demo/pods/p/exec"],
        ):
            with self.assertRaises(ValueError):
                K8sClient._validate_kubectl_args(args)

    def test_kubectl_allowlist_accepts_reads_and_self_reviews(self):
        K8sClient._validate_kubectl_args(["get", "--raw", "/api"])
        K8sClient._validate_kubectl_args(
            ["config", "view", "--minify", "--raw=false", "-o", "json"]
        )
        K8sClient._validate_kubectl_args(
            [
                "create",
                "--raw",
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                "-f",
                "-",
            ]
        )

    def test_official_backend_rejects_every_non_review_post(self):
        client = object.__new__(K8sClient)
        client.api_client = object()
        with self.assertRaises(ValueError):
            client._official_request("POST", "/api/v1/namespaces", {})
        with self.assertRaises(ValueError):
            client._official_request(
                "GET", "/api/v1/namespaces/demo/pods/p/proxy/metrics"
            )

    def test_explicit_token_clears_kubeconfig_client_certificate_for_kubectl(self):
        client = object.__new__(K8sClient)
        client._kubectl = "kubectl"
        client.server = None
        client.kubeconfig = None
        client.context = "demo"
        client.token = "test-token"
        client.certificate_authority = None
        client.client_certificate = None
        client.client_key = None
        client.impersonate_user = None
        client.impersonate_groups = []
        client.insecure_skip_tls_verify = False
        command = client._kubectl_base()
        self.assertIn("--token", command)
        self.assertIn("--client-certificate=", command)
        self.assertIn("--client-key=", command)

    def test_retry_classifier_never_retries_authorization_failures(self):
        self.assertTrue(K8sClient._is_transient(429, "Too Many Requests"))
        self.assertTrue(K8sClient._is_transient(503, "ServiceUnavailable"))
        self.assertTrue(K8sClient._is_transient(None, "connection reset by peer"))
        self.assertFalse(K8sClient._is_transient(401, "Unauthorized"))
        self.assertFalse(K8sClient._is_transient(403, "Forbidden"))

    def test_status_classifier_recognizes_not_found(self):
        self.assertEqual(K8sClient._status_from_error("Error from server (NotFound)"), 404)
        self.assertEqual(K8sClient._status_from_error("HTTP 404 Not Found"), 404)

    def test_kubectl_probe_get_returns_status_without_parsing_body(self):
        client = object.__new__(K8sClient)
        client.api_client = None
        client.timeout = 1
        client._kubectl_base = lambda: ["kubectl"]
        response = SimpleNamespace(returncode=0, stdout=b"plain text", stderr=b"")
        with patch("src.k8s.client.subprocess.run", return_value=response):
            self.assertEqual(client.probe_get("/debug/pprof/"), (200, 10))

    def test_probe_get_still_rejects_proxy_paths(self):
        client = object.__new__(K8sClient)
        client.api_client = None
        for unsafe_path in (
            "/api/v1/nodes/node-1/proxy/metrics",
            "/api/v1/nodes/node-1%2Fproxy%2Fmetrics",
            "/api/v1/nodes/node-1%252Fproxy%252Fmetrics",
            "https://attacker.invalid/debug/pprof/",
            "//attacker.invalid/debug/pprof/",
        ):
            with self.subTest(path=unsafe_path), self.assertRaises(ValueError):
                client.probe_get(unsafe_path)

    def test_kubectl_transient_failure_is_retried(self):
        client = object.__new__(K8sClient)
        client.retries = 2
        client.timeout = 1
        client._kubectl_base = lambda: ["kubectl"]
        responses = [
            SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="Error from server (ServiceUnavailable): 503",
            ),
            SimpleNamespace(returncode=0, stdout='{"versions": ["v1"]}', stderr=""),
        ]
        with patch("src.k8s.client.subprocess.run", side_effect=responses) as run:
            with patch.object(K8sClient, "_retry_pause"):
                result = client._kubectl_run(["get", "--raw", "/api"])
        self.assertEqual(result["versions"], ["v1"])
        self.assertEqual(run.call_count, 2)

    def test_kubectl_forbidden_failure_is_not_retried(self):
        client = object.__new__(K8sClient)
        client.retries = 5
        client.timeout = 1
        client._kubectl_base = lambda: ["kubectl"]
        response = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Error from server (Forbidden): forbidden",
        )
        with patch("src.k8s.client.subprocess.run", return_value=response) as run:
            with self.assertRaises(Exception):
                client._kubectl_run(["get", "--raw", "/api"])
        self.assertEqual(run.call_count, 1)

    def test_namespace_names_cannot_inject_an_api_path(self):
        self.assertTrue(is_valid_namespace_name("team-a"))
        self.assertFalse(is_valid_namespace_name("../nodes"))
        self.assertFalse(is_valid_namespace_name("default?watch=true"))

    def test_malformed_list_response_fails_with_a_bounded_api_error(self):
        client = object.__new__(K8sClient)
        client.get = lambda _path: {"items": {"not": "an array"}}
        with self.assertRaises(APIError):
            client.list_items("/api/v1/pods")

    def test_client_close_always_attempts_credential_cleanup(self):
        client = object.__new__(K8sClient)
        client.api_client = SimpleNamespace(close=Mock(side_effect=RuntimeError("close")))
        client._cleanup_temporary_kubeconfig = Mock()
        with self.assertRaises(RuntimeError):
            client.close()
        client._cleanup_temporary_kubeconfig.assert_called_once_with()

    def test_failed_temp_credential_cleanup_retains_path_for_atexit_retry(self):
        client = object.__new__(K8sClient)
        client._temporary_kubeconfig_path = "/tmp/k8speass-test.kubeconfig"
        with patch("src.k8s.client.Path.unlink", side_effect=PermissionError("denied")):
            with self.assertRaises(RuntimeError):
                client._cleanup_temporary_kubeconfig()
        self.assertEqual(
            client._temporary_kubeconfig_path, "/tmp/k8speass-test.kubeconfig"
        )

    def test_malformed_discovery_is_partial_instead_of_fatal(self):
        class MalformedDiscoveryClient:
            def get(self, path):
                if path == "/api":
                    return {"versions": "v1"}
                return {"groups": [None, {"versions": "v1"}]}

        resources, warnings = discover_api_resources(MalformedDiscoveryClient())
        self.assertEqual(resources, [])
        self.assertGreaterEqual(len(warnings), 3)

    def test_noninteractive_slow_work_is_skipped(self):
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("")
            self.assertFalse(
                confirm_slow_operation("slow", force=False, no_ask=False)
            )
            self.assertTrue(
                confirm_slow_operation("slow", force=True, no_ask=True)
            )
        finally:
            sys.stdin = old_stdin


class PermissionModelTests(unittest.TestCase):
    @staticmethod
    def _scanner_with_probe(status, size=0):
        scanner = object.__new__(K8sPEASS)
        scanner.client = SimpleNamespace(probe_get=Mock(return_value=(status, size)))
        scanner._nonresource_probe_cache = {}
        return scanner

    def test_high_nonresource_url_requires_live_safe_endpoint(self):
        finding = PermissionFinding(
            key=PermissionKey("get", non_resource_url="/debug/*"),
            allowed=True,
            severity="high",
            explanation="sensitive",
        )
        scanner = self._scanner_with_probe(200, 123)
        confirmed = scanner._validate_high_nonresource_findings([finding])[0]
        self.assertEqual(confirmed.severity, "high")
        self.assertTrue(confirmed.resource_served)
        self.assertIn("123 bytes", confirmed.explanation)

        scanner = self._scanner_with_probe(404)
        dormant = scanner._validate_high_nonresource_findings([finding])[0]
        self.assertEqual(dormant.severity, "low")
        self.assertEqual(dormant.potential_severity, "high")
        self.assertFalse(dormant.resource_served)

    def test_unbounded_nonresource_pattern_is_conditional_not_high(self):
        finding = PermissionFinding(
            key=PermissionKey("get", non_resource_url="/debug/custom"),
            allowed=True,
            severity="high",
        )
        scanner = self._scanner_with_probe(200)
        conditional = scanner._validate_high_nonresource_findings([finding])[0]
        self.assertEqual(conditional.severity, "medium")
        self.assertEqual(conditional.potential_severity, "high")
        scanner.client.probe_get.assert_not_called()

    def test_nonresource_probe_results_are_cached(self):
        scanner = self._scanner_with_probe(200, 5)
        findings = [
            PermissionFinding(
                key=PermissionKey("get", non_resource_url="/debug/*"),
                allowed=True,
                severity="high",
            ),
            PermissionFinding(
                key=PermissionKey("get", non_resource_url="*"),
                allowed=True,
                severity="high",
            ),
        ]
        scanner._validate_high_nonresource_findings(findings)
        scanner.client.probe_get.assert_called_once_with("/debug/pprof/")

    def test_unserved_explicit_rbac_grant_is_downgraded(self):
        scanner = object.__new__(K8sPEASS)
        scanner.coverage = Coverage(discovery_complete=True)
        finding = PermissionFinding(
            key=PermissionKey(
                "patch",
                group="certificates.k8s.io",
                resource="clustertrustbundles",
            ),
            allowed=True,
            severity="high",
            explanation="potential",
        )
        normalized = scanner._normalize_summarized_findings([finding], [])[0]
        self.assertEqual(normalized.severity, "low")
        self.assertEqual(normalized.potential_severity, "high")
        self.assertFalse(normalized.resource_served)
        self.assertIn("not served", normalized.explanation)

    def test_unadvertised_operation_is_dormant_but_special_verbs_are_preserved(self):
        scanner = object.__new__(K8sPEASS)
        scanner.coverage = Coverage(discovery_complete=True)
        resources = [
            APIResource(
                group="",
                version="v1",
                resource="pods",
                subresource="log",
                namespaced=True,
                verbs=("get",),
            ),
            APIResource(
                group="rbac.authorization.k8s.io",
                version="v1",
                resource="roles",
                namespaced=True,
                verbs=("create", "get", "patch", "update"),
            ),
        ]
        findings = [
            PermissionFinding(
                key=PermissionKey(
                    "create", resource="pods", subresource="log", namespace="demo"
                ),
                allowed=True,
                severity="medium",
            ),
            PermissionFinding(
                key=PermissionKey(
                    "escalate",
                    group="rbac.authorization.k8s.io",
                    resource="roles",
                    namespace="demo",
                ),
                allowed=True,
                severity="critical",
            ),
        ]
        dormant, special = scanner._normalize_summarized_findings(findings, resources)
        self.assertEqual(dormant.severity, "low")
        self.assertFalse(dormant.resource_served)
        self.assertEqual(special.severity, "critical")
        self.assertTrue(special.resource_served)

    def test_uninstalled_policy_resource_is_dormant_even_for_use(self):
        scanner = object.__new__(K8sPEASS)
        scanner.coverage = Coverage(discovery_complete=True)
        finding = PermissionFinding(
            key=PermissionKey(
                "use",
                group="security.openshift.io",
                resource="securitycontextconstraints",
            ),
            allowed=True,
            severity="medium",
        )
        normalized = scanner._normalize_summarized_findings([finding], [])[0]
        self.assertEqual(normalized.severity, "low")
        self.assertEqual(normalized.potential_severity, "medium")
        self.assertFalse(normalized.resource_served)

    def test_exact_confirmation_preserves_served_metadata(self):
        scanner = object.__new__(K8sPEASS)
        scanner.coverage = Coverage()
        key = PermissionKey("get", resource="secrets", namespace="demo")
        summarized = PermissionFinding(
            key=key,
            allowed=True,
            confidence="summarized",
            severity="critical",
            resource_served=True,
            explanation="served endpoint evidence",
        )
        scanner._run_access_reviews = Mock(
            return_value=[
                PermissionFinding(
                    key=key,
                    allowed=True,
                    confidence="confirmed",
                    severity="critical",
                )
            ]
        )
        confirmed = scanner._confirm_high_risk([summarized])
        self.assertTrue(confirmed[0].resource_served)
        self.assertEqual(confirmed[0].explanation, "served endpoint evidence")

    def test_resource_names_generate_named_and_selector_findings(self):
        status = {
            "resourceRules": [
                {
                    "verbs": ["get", "list"],
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "resourceNames": ["only-this"],
                }
            ]
        }
        findings = findings_from_rules(status, "demo")
        get_finding = next(item for item in findings if item.key.verb == "get")
        list_finding = next(item for item in findings if item.key.verb == "list")
        self.assertEqual(get_finding.key.name, "only-this")
        self.assertEqual(list_finding.key.field_selector, "metadata.name=only-this")

    def test_sensitive_subresources_are_not_flattened(self):
        key = PermissionKey(
            "create",
            resource="serviceaccounts",
            subresource="token",
            namespace="demo",
        )
        severity, explanation = classify_permission(key)
        self.assertEqual(severity, "critical")
        self.assertIn("token", explanation.lower())

    def test_permission_risk_matrix_covers_offensive_control_paths(self):
        cases = [
            ("critical", PermissionKey("get", resource="*")),
            ("high", PermissionKey("create", resource="*")),
            ("critical", PermissionKey("list", resource="secrets")),
            ("high", PermissionKey("patch", resource="secrets")),
            (
                "critical",
                PermissionKey("create", resource="serviceaccounts", subresource="token"),
            ),
            ("critical", PermissionKey("get", resource="nodes", subresource="proxy")),
            ("medium", PermissionKey("create", resource="nodes", subresource="checkpoint")),
            (
                "critical",
                PermissionKey(
                    "bind", group="rbac.authorization.k8s.io", resource="clusterroles"
                ),
            ),
            (
                "critical",
                PermissionKey(
                    "escalate", group="rbac.authorization.k8s.io", resource="roles"
                ),
            ),
            ("high", PermissionKey("impersonate", resource="groups")),
            (
                "critical",
                PermissionKey(
                    "impersonate",
                    resource="serviceaccounts",
                    name="system:serviceaccount:demo:builder",
                ),
            ),
            (
                "high",
                PermissionKey(
                    "approve", group="certificates.k8s.io", resource="signers"
                ),
            ),
            (
                "medium",
                PermissionKey("sign", group="certificates.k8s.io", resource="signers"),
            ),
            (
                "medium",
                PermissionKey(
                    "attest", group="certificates.k8s.io", resource="signers"
                ),
            ),
            (
                "high",
                PermissionKey(
                    "create",
                    group="certificates.k8s.io",
                    resource="certificatesigningrequests",
                ),
            ),
            ("medium", PermissionKey("create", resource="podcertificaterequests")),
            (
                "high",
                PermissionKey(
                    "update",
                    group="certificates.k8s.io",
                    resource="certificatesigningrequests",
                    subresource="approval",
                ),
            ),
            ("medium", PermissionKey("use", resource="*")),
            ("high", PermissionKey("create", resource="pods", subresource="exec")),
            (
                "high",
                PermissionKey("patch", resource="pods", subresource="ephemeralcontainers"),
            ),
            ("medium", PermissionKey("create", resource="pods", subresource="eviction")),
            ("high", PermissionKey("create", resource="bindings")),
            ("high", PermissionKey("get", resource="services", subresource="proxy")),
            ("medium", PermissionKey("patch", resource="nodes", subresource="status")),
            ("high", PermissionKey("create", group="apps", resource="daemonsets")),
            (
                "medium",
                PermissionKey(
                    "patch",
                    group="rbac.authorization.k8s.io",
                    resource="clusterrolebindings",
                ),
            ),
            (
                "high",
                PermissionKey(
                    "patch",
                    group="admissionregistration.k8s.io",
                    resource="validatingadmissionpolicybindings",
                ),
            ),
            ("high", PermissionKey("create", resource="namespaces")),
            (
                "medium",
                PermissionKey(
                    "use",
                    group="security.openshift.io",
                    resource="securitycontextconstraints",
                ),
            ),
            (
                "medium",
                PermissionKey(
                    "patch",
                    group="kyverno.io",
                    resource="policyexceptions",
                ),
            ),
            (
                "high",
                PermissionKey(
                    "delete", group="networking.k8s.io", resource="networkpolicies"
                ),
            ),
            ("high", PermissionKey("patch", resource="services")),
            (
                "high",
                PermissionKey(
                    "create", group="discovery.k8s.io", resource="endpointslices"
                ),
            ),
            ("medium", PermissionKey("patch", resource="servicecidrs")),
            ("high", PermissionKey("create", resource="persistentvolumes")),
            ("medium", PermissionKey("create", resource="volumesnapshotcontents")),
            ("medium", PermissionKey("patch", resource="customresourcedefinitions")),
            ("medium", PermissionKey("create", resource="deviceclasses")),
            (
                "medium",
                PermissionKey(
                    "arbitrary-node:patch",
                    group="resource.k8s.io",
                    resource="resourceclaims",
                    subresource="driver",
                ),
            ),
            (
                "medium",
                PermissionKey(
                    "request-serviceaccounts-token-audience",
                    resource="registry.example",
                    name="build-sa",
                ),
            ),
            ("medium", PermissionKey("delete", resource="nodes")),
            ("medium", PermissionKey("patch", resource="serviceaccounts")),
            (
                "high",
                PermissionKey(
                    "patch",
                    resource="configmaps",
                    namespace="kube-system",
                    name="aws-auth",
                ),
            ),
            ("high", PermissionKey("update", resource="configmaps")),
            ("high", PermissionKey("create", resource="configmaps")),
            ("medium", PermissionKey("delete", resource="pods")),
            ("high", PermissionKey("patch", resource="pods")),
            (
                "medium",
                PermissionKey(
                    "create",
                    group="argoproj.io",
                    resource="applications",
                ),
            ),
            ("medium", PermissionKey("get", resource="pods", subresource="log")),
            ("medium", PermissionKey("list", resource="pods")),
            ("medium", PermissionKey("patch", resource="leases")),
            (
                "medium",
                PermissionKey(
                    "patch", group="wgpolicyk8s.io", resource="policyreports"
                ),
            ),
            ("medium", PermissionKey("get", non_resource_url="/metrics")),
            ("low", PermissionKey("get", resource="namespaces")),
            ("low", PermissionKey("get", non_resource_url="/version")),
        ]
        for expected, key in cases:
            with self.subTest(permission=key.human()):
                severity, explanation = classify_permission(key)
                self.assertEqual(severity, expected)
                self.assertTrue(explanation)

    def test_new_minikube_verified_paths_are_high(self):
        cases = (
            PermissionKey("create", resource="services"),
            PermissionKey("create", resource="endpoints"),
            PermissionKey(
                "create", group="discovery.k8s.io", resource="endpointslices"
            ),
            PermissionKey("patch", resource="pods", subresource="status"),
            PermissionKey("patch", resource="services", subresource="status"),
            PermissionKey(
                "delete",
                group="admissionregistration.k8s.io",
                resource="validatingadmissionpolicies",
            ),
            PermissionKey(
                "patch",
                group="admissionregistration.k8s.io",
                resource="validatingwebhookconfigurations",
            ),
            PermissionKey(
                "create",
                group="admissionregistration.k8s.io",
                resource="validatingwebhookconfigurations",
            ),
            PermissionKey(
                "create",
                group="admissionregistration.k8s.io",
                resource="mutatingwebhookconfigurations",
            ),
            PermissionKey(
                "delete",
                group="admissionregistration.k8s.io",
                resource="mutatingwebhookconfigurations",
            ),
            PermissionKey(
                "create",
                group="admissionregistration.k8s.io",
                resource="mutatingadmissionpolicies",
            ),
            PermissionKey(
                "patch",
                group="admissionregistration.k8s.io",
                resource="mutatingadmissionpolicybindings",
            ),
            PermissionKey(
                "create", group="networking.k8s.io", resource="networkpolicies"
            ),
            PermissionKey(
                "create", group="networking.k8s.io", resource="ingresses"
            ),
            PermissionKey(
                "patch", group="networking.k8s.io", resource="ingresses"
            ),
        )
        for key in cases:
            with self.subTest(permission=key.human()):
                severity, _ = classify_permission(key)
                self.assertEqual(severity, "high")

    def test_controller_subresources_are_not_controller_template_writes(self):
        for subresource in ("status", "scale"):
            severity, _ = classify_permission(
                PermissionKey(
                    "patch", group="apps", resource="deployments", subresource=subresource
                )
            )
            self.assertEqual(severity, "medium")

    def test_admission_configuration_derives_only_exact_sensitive_checks(self):
        admission = [
            {
                "type": "validating admission policy bindings",
                "name": "guard-binding",
                "configuration": {
                    "matchConditions": [
                        {
                            "expression": "object.metadata.name == 'candidate' && !authorizer.group('example.io').resource('guards').namespace('demo').name('breakglass').check('breakglass').allowed()"
                        },
                        {
                            "expression": "authorizer.group('').resource('pods').name('x').check('delete').allowed()"
                        },
                    ],
                    "parameterTarget": {
                        "group": "example.io",
                        "resource": "guards",
                        "namespace": "demo",
                        "name": "guard",
                        "exists": True,
                        "parameterNotFoundAction": "Allow",
                        "usedByDenyValidation": True,
                    },
                },
            }
        ]
        risks = admission_sensitive_permissions(admission)
        self.assertIn(
            PermissionKey("breakglass", "example.io", resource="guards", namespace="demo", name="breakglass"),
            risks,
        )
        for verb in ("patch", "update", "delete"):
            self.assertIn(
                PermissionKey(verb, "example.io", resource="guards", namespace="demo", name="guard"),
                risks,
            )
        self.assertNotIn(
            PermissionKey("delete", resource="pods", name="x"), risks
        )

    def test_fail_open_webhook_derives_exact_service_and_scale_checks(self):
        admission = [
            {
                "type": "validating webhooks",
                "name": "guard",
                "configuration": {
                    "failOpenTargets": [
                        {
                            "namespace": "policy-system",
                            "name": "guard-webhook",
                            "exists": True,
                            "singleReadyDeployment": {
                                "namespace": "policy-system",
                                "name": "guard-controller",
                            },
                        }
                    ]
                },
            }
        ]
        risks = admission_sensitive_permissions(admission)
        self.assertIn(
            PermissionKey(
                "delete", resource="services", namespace="policy-system", name="guard-webhook"
            ),
            risks,
        )
        for verb in ("patch", "update"):
            self.assertIn(
                PermissionKey(
                    verb,
                    group="apps",
                    resource="deployments",
                    subresource="scale",
                    namespace="policy-system",
                    name="guard-controller",
                ),
                risks,
            )
        self.assertIn(
            PermissionKey(
                "delete",
                group="apps",
                resource="deployments",
                namespace="policy-system",
                name="guard-controller",
            ),
            risks,
        )

    def test_constrained_impersonation_is_conditional_and_impact_aware(self):
        cases = (
            (
                "high",
                PermissionKey(
                    "impersonate:user-info",
                    group="authentication.k8s.io",
                    resource="users",
                ),
            ),
            (
                "high",
                PermissionKey(
                    "impersonate-on:user-info:get", resource="secrets"
                ),
            ),
            (
                "medium",
                PermissionKey(
                    "impersonate-on:user-info:get", resource="namespaces"
                ),
            ),
            (
                "medium",
                PermissionKey(
                    "impersonate",
                    group="authentication.k8s.io",
                    resource="uids",
                ),
            ),
        )
        for expected, key in cases:
            with self.subTest(permission=key.human()):
                severity, explanation = classify_permission(key)
                self.assertEqual(severity, expected)
                self.assertIn("impersonat", explanation.lower())

    def test_builtin_names_in_unrelated_api_groups_are_not_overrated(self):
        cases = (
            PermissionKey("get", group="example.test", resource="secrets"),
            PermissionKey("patch", group="example.test", resource="pods"),
            PermissionKey("create", group="example.test", resource="services"),
            PermissionKey("get", group="apps", resource="*"),
        )
        for key in cases:
            with self.subTest(permission=key.human()):
                severity, _ = classify_permission(key)
                self.assertNotIn(severity, {"critical", "high"})

        core_wildcard, _ = classify_permission(PermissionKey("get", resource="*"))
        all_groups_wildcard, _ = classify_permission(
            PermissionKey("get", group="*", resource="*")
        )
        self.assertEqual(core_wildcard, "critical")
        self.assertEqual(all_groups_wildcard, "critical")

    def test_constrained_impersonation_virtual_resources_survive_discovery(self):
        for key in (
            PermissionKey(
                "impersonate:user-info",
                group="authentication.k8s.io",
                resource="users",
            ),
            PermissionKey(
                "impersonate:serviceaccount",
                group="authentication.k8s.io",
                resource="serviceaccounts",
            ),
            PermissionKey(
                "impersonate:arbitrary-node",
                group="authentication.k8s.io",
                resource="nodes",
            ),
        ):
            with self.subTest(permission=key.human()):
                self.assertTrue(K8sPEASS._authorization_without_discovery(key))
                self.assertTrue(K8sPEASS._is_special_verb_for_served_resource(key))

    def test_zero_visibility_fallback_checks_include_new_high_paths(self):
        scanner = object.__new__(K8sPEASS)
        scanner._run_access_reviews = Mock(side_effect=lambda candidates: candidates)
        candidates = scanner._fallback_checks(["demo"], [])
        identities = {
            (key.verb, key.group, key.resource, key.subresource, key.namespace)
            for key in candidates
        }
        expected = {
            ("patch", "", "pods", "status", "demo"),
            ("patch", "", "services", "status", "demo"),
            ("create", "", "services", "", "demo"),
            ("create", "", "endpoints", "", "demo"),
            ("create", "discovery.k8s.io", "endpointslices", "", "demo"),
            ("create", "", "configmaps", "", "demo"),
            ("impersonate:user-info", "authentication.k8s.io", "users", "", ""),
            ("impersonate-on:user-info:get", "", "secrets", "", "demo"),
            (
                "patch",
                "admissionregistration.k8s.io",
                "mutatingadmissionpolicies",
                "",
                "",
            ),
        }
        self.assertTrue(expected.issubset(identities))

    def test_exhaustive_checks_use_correct_virtual_impersonation_groups(self):
        candidates = K8sPEASS._exhaustive_candidates([], ["demo"])
        identities = {
            (key.verb, key.group, key.resource, key.namespace) for key in candidates
        }
        self.assertIn(("impersonate", "", "users", ""), identities)
        self.assertIn(("impersonate", "", "groups", ""), identities)
        self.assertIn(
            ("impersonate:user-info", "authentication.k8s.io", "users", ""),
            identities,
        )
        self.assertIn(
            (
                "impersonate:serviceaccount",
                "authentication.k8s.io",
                "serviceaccounts",
                "demo",
            ),
            identities,
        )

    def test_aws_auth_needs_platform_evidence_and_stays_high(self):
        severity, _ = classify_permission(
            PermissionKey(
                "patch", resource="configmaps", namespace="application", name="aws-auth"
            )
        )
        self.assertEqual(severity, "high")

    def test_special_verbs_are_not_critical_on_unrelated_resources(self):
        for key in (
            PermissionKey("bind", resource="pods"),
            PermissionKey("escalate", resource="configmaps"),
            PermissionKey("impersonate", resource="pods"),
            PermissionKey("approve", resource="pods"),
        ):
            with self.subTest(permission=key.human()):
                severity, _ = classify_permission(key)
                self.assertNotEqual(severity, "critical")

    def test_no_opinion_exact_review_does_not_erase_positive_rules_review(self):
        key = PermissionKey(
            "list",
            resource="secrets",
            namespace="demo",
            field_selector="metadata.name=only-this",
        )
        summarized = PermissionFinding(key=key, allowed=True, confidence="summarized")
        no_opinion = PermissionFinding(key=key, allowed=False, confidence="confirmed")
        merged = K8sPEASS._merge_findings([summarized, no_opinion])
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].allowed)
        self.assertEqual(merged[0].confidence, "summarized")

    def test_malformed_rule_arrays_do_not_expand_strings_character_by_character(self):
        status = {
            "resourceRules": [
                {"verbs": "get", "apiGroups": "", "resources": "secrets"}
            ],
            "nonResourceRules": [{"verbs": "get", "nonResourceURLs": "/api"}],
        }
        self.assertEqual(findings_from_rules(status, "demo"), [])

    def test_allowed_workload_write_is_marked_admission_unknown(self):
        finding = PermissionFinding(
            key=PermissionKey("create", resource="pods", namespace="demo"),
            allowed=True,
        )
        admission = [
            {
                "type": "Pod Security Admission namespace labels",
                "name": "demo",
                "configuration": {
                    "pod-security.kubernetes.io/enforce": "restricted"
                },
            }
        ]
        result = K8sPEASS._annotate_admission([finding], admission)[0]
        self.assertIn("did not send a write probe", result.admission)
        self.assertIn("restricted", result.admission)

    def test_live_admission_correlation_elevates_exact_allowed_permission(self):
        key = PermissionKey("breakglass", "example.io", resource="guards", name="x")
        finding = PermissionFinding(key=key, allowed=True, severity="low")
        result = K8sPEASS._annotate_admission(
            [finding], [], {key: "Observed exact admission bypass."}
        )[0]
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.explanation, "Observed exact admission bypass.")

    def test_json_report_is_atomic_private_and_cleans_failed_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "report.json")
            scanner = object.__new__(K8sPEASS)
            scanner.out_path = target
            scanner._write_json({"ok": True})
            with open(target, encoding="utf-8") as report:
                self.assertEqual(json.load(report), {"ok": True})
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

            scanner.out_path = os.path.join(directory, "invalid.json")
            with self.assertRaises(TypeError):
                scanner._write_json({"not-json": {object()}})
            self.assertEqual(os.listdir(directory), ["report.json"])


if __name__ == "__main__":
    unittest.main()
