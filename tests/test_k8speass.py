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
from src.k8s.models import PermissionFinding, PermissionKey
from src.k8s.passive import is_valid_namespace_name
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
