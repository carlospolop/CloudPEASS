"""Resilient, read-only Kubernetes API transport.

The only POST endpoints allowed here are virtual self-review APIs. They do not
persist Kubernetes objects. Every other request is forced to use HTTP GET.
"""

from __future__ import annotations

import atexit
import inspect
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit


SAFE_REVIEW_ENDPOINTS = {
    "/apis/authentication.k8s.io/v1/selfsubjectreviews",
    "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
    "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
}


@dataclass
class APIError(Exception):
    message: str
    status: int | None = None
    body: str = ""

    def __str__(self) -> str:
        status = f"HTTP {self.status}: " if self.status else ""
        return status + self.message


def _json_from_text(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise APIError(f"API returned malformed JSON: {exc}", body=text[:1000]) from exc
    if not isinstance(value, dict):
        raise APIError("API returned a JSON value that is not an object", body=text[:1000])
    return value


class K8sClient:
    """Use the official client when available and fall back to kubectl."""

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
        timeout: int = 15,
        retries: int = 2,
    ) -> None:
        self.kubeconfig = str(Path(kubeconfig).expanduser()) if kubeconfig else None
        self.context = context
        self.server = server
        self.token = token
        self.certificate_authority = (
            str(Path(certificate_authority).expanduser())
            if certificate_authority
            else None
        )
        self.client_certificate = (
            str(Path(client_certificate).expanduser()) if client_certificate else None
        )
        self.client_key = str(Path(client_key).expanduser()) if client_key else None
        self.impersonate_user = impersonate_user
        self.impersonate_groups = impersonate_groups or []
        self.insecure_skip_tls_verify = insecure_skip_tls_verify
        self.timeout = max(1, min(int(timeout), 300))
        self.retries = max(0, min(int(retries), 5))
        self.backend = ""
        self.api_client = None
        self._temporary_kubeconfig_path: str | None = None
        self._source_context_name = context or ""
        self._kubectl = shutil.which("kubectl")
        self._load_official_client()
        if self.api_client is not None and len(self.impersonate_groups) > 1:
            if not self._kubectl:
                raise RuntimeError(
                    "Multiple --as-group values require kubectl because the Python "
                    "client cannot preserve repeated impersonation headers."
                )
            self.api_client = None
            self.backend = "kubectl"
        if self.api_client is None:
            if not self._kubectl:
                raise RuntimeError(
                    "Neither the Python kubernetes package nor kubectl is available. "
                    "Install requirements.txt or install kubectl."
                )
            if self.token and not self.server:
                self._prepare_token_only_kubeconfig()
            self.backend = "kubectl"

    @staticmethod
    def _in_cluster_available() -> bool:
        return bool(
            os.getenv("KUBERNETES_SERVICE_HOST")
            and Path("/var/run/secrets/kubernetes.io/serviceaccount/token").is_file()
        )

    def _load_official_client(self) -> None:
        try:
            from kubernetes import client as kube_client
            from kubernetes import config as kube_config
        except ImportError:
            return

        try:
            if self.server:
                cfg = kube_client.Configuration()
                cfg.host = self.server.rstrip("/")
                cfg.verify_ssl = not self.insecure_skip_tls_verify
                if self.certificate_authority:
                    cfg.ssl_ca_cert = self.certificate_authority
                if self.client_certificate:
                    cfg.cert_file = self.client_certificate
                if self.client_key:
                    cfg.key_file = self.client_key
                if self.token:
                    cfg.api_key["BearerToken"] = self.token
                    cfg.api_key_prefix["BearerToken"] = "Bearer"
                    cfg.api_key["authorization"] = self.token
                    cfg.api_key_prefix["authorization"] = "Bearer"
            elif self._in_cluster_available() and not self.kubeconfig and not self.context:
                kube_config.load_incluster_config()
                cfg = kube_client.Configuration.get_default_copy()
            else:
                kube_config.load_kube_config(
                    config_file=self.kubeconfig,
                    context=self.context,
                    persist_config=False,
                )
                cfg = kube_client.Configuration.get_default_copy()
                if self.token:
                    # An explicitly supplied token must not be shadowed by a
                    # client certificate or kubeconfig exec credential.
                    cfg.cert_file = None
                    cfg.key_file = None
                    cfg.username = None
                    cfg.password = None
                    cfg.refresh_api_key_hook = None
                    cfg.api_key = {}
                    cfg.api_key_prefix = {}
                    cfg.api_key["BearerToken"] = self.token
                    cfg.api_key_prefix["BearerToken"] = "Bearer"
                    cfg.api_key["authorization"] = self.token
                    cfg.api_key_prefix["authorization"] = "Bearer"
                if self.certificate_authority:
                    cfg.ssl_ca_cert = self.certificate_authority
                if self.client_certificate:
                    cfg.cert_file = self.client_certificate
                if self.client_key:
                    cfg.key_file = self.client_key
                if self.insecure_skip_tls_verify:
                    cfg.verify_ssl = False
            cfg.connection_pool_maxsize = max(getattr(cfg, "connection_pool_maxsize", 4), 16)
            self.api_client = kube_client.ApiClient(cfg)
            self._modern_call_api = (
                "response_types_map"
                in inspect.signature(self.api_client.call_api).parameters
            )
            self.backend = "python-kubernetes"
        except Exception:
            self.api_client = None

    def _kubectl_base(self) -> list[str]:
        if not self._kubectl:
            raise RuntimeError("kubectl is not installed")
        command = [self._kubectl]
        temporary_kubeconfig = getattr(self, "_temporary_kubeconfig_path", None)
        if temporary_kubeconfig:
            command.extend(["--kubeconfig", temporary_kubeconfig])
        elif self.server and not self.kubeconfig:
            command.extend(["--kubeconfig", os.devnull])
        elif self.kubeconfig:
            command.extend(["--kubeconfig", self.kubeconfig])
        if self.context and not self.server and not temporary_kubeconfig:
            command.extend(["--context", self.context])
        if self.server:
            command.extend(["--server", self.server])
        if self.token and not temporary_kubeconfig:
            command.extend(["--token", self.token])
            if not self.client_certificate and not self.client_key:
                command.extend(["--client-certificate=", "--client-key="])
        if self.certificate_authority:
            command.extend(["--certificate-authority", self.certificate_authority])
        if self.client_certificate:
            command.extend(["--client-certificate", self.client_certificate])
        if self.client_key:
            command.extend(["--client-key", self.client_key])
        if self.impersonate_user:
            command.extend(["--as", self.impersonate_user])
        for group in self.impersonate_groups:
            command.extend(["--as-group", group])
        if self.insecure_skip_tls_verify:
            command.append("--insecure-skip-tls-verify=true")
        return command

    def _prepare_token_only_kubeconfig(self) -> None:
        """Copy only cluster TLS data and the explicit token into a private file."""
        if not self._kubectl:
            raise RuntimeError("kubectl is not installed")
        command = [self._kubectl]
        if self.kubeconfig:
            command.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            command.extend(["--context", self.context])
        command.extend(["config", "view", "--minify", "--raw=false", "-o", "json"])
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Timed out while isolating explicit bearer-token credentials"
            ) from exc
        if completed.returncode != 0:
            raise RuntimeError(
                "Cannot isolate the explicit bearer token from kubeconfig credentials: "
                + (completed.stderr or completed.stdout).strip()
            )
        data = _json_from_text(completed.stdout)
        clusters = data.get("clusters") or []
        contexts = data.get("contexts") or []
        if not clusters:
            raise RuntimeError("Selected kubeconfig context has no cluster")
        cluster = clusters[0].get("cluster") or {}
        allowed_cluster_keys = {
            "server",
            "certificate-authority",
            "certificate-authority-data",
            "insecure-skip-tls-verify",
            "tls-server-name",
            "proxy-url",
            "disable-compression",
        }
        safe_cluster = {
            key: value for key, value in cluster.items() if key in allowed_cluster_keys
        }
        ca_path = safe_cluster.get("certificate-authority")
        if ca_path and not Path(str(ca_path)).expanduser().is_absolute():
            configured_path = self.kubeconfig or os.getenv("KUBECONFIG") or "~/.kube/config"
            config_file = Path(str(configured_path).split(os.pathsep, 1)[0]).expanduser()
            safe_cluster["certificate-authority"] = str(
                (config_file.parent / str(ca_path)).resolve()
            )
        if not safe_cluster.get("server"):
            raise RuntimeError("Selected kubeconfig context has no API server URL")
        context_data = (contexts[0].get("context") or {}) if contexts else {}
        self._source_context_name = str(
            data.get("current-context") or self.context or ""
        )
        isolated = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{"name": "cluster", "cluster": safe_cluster}],
            "contexts": [
                {
                    "name": "k8speass-token",
                    "context": {
                        "cluster": "cluster",
                        "user": "token",
                        "namespace": context_data.get("namespace") or "default",
                    },
                }
            ],
            "current-context": "k8speass-token",
            "users": [{"name": "token", "user": {"token": self.token}}],
        }
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="k8speass-",
            suffix=".kubeconfig",
            delete=False,
        )
        try:
            json.dump(isolated, handle)
            handle.flush()
            os.chmod(handle.name, 0o600)
            self._temporary_kubeconfig_path = handle.name
        except Exception:
            Path(handle.name).unlink(missing_ok=True)
            raise
        finally:
            handle.close()
        atexit.register(self._cleanup_temporary_kubeconfig)

    def _cleanup_temporary_kubeconfig(self) -> None:
        path = self._temporary_kubeconfig_path
        if not path:
            return
        try:
            Path(path).unlink(missing_ok=True)
        except OSError as exc:
            # Keep the path so the registered atexit handler can try again.
            raise RuntimeError(
                f"Could not remove temporary kubeconfig {path}: {exc}"
            ) from exc
        else:
            self._temporary_kubeconfig_path = None

    def close(self) -> None:
        close = getattr(self.api_client, "close", None)
        try:
            if callable(close):
                close()
        finally:
            self._cleanup_temporary_kubeconfig()

    def _kubectl_run(
        self, args: list[str], body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self._validate_kubectl_args(args)
        command = self._kubectl_base() + args
        last_error: APIError | None = None
        for attempt in range(self.retries + 1):
            try:
                completed = subprocess.run(
                    command,
                    input=json.dumps(body) if body is not None else None,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                last_error = APIError(f"kubectl timed out after {self.timeout}s")
                if attempt < self.retries:
                    self._retry_pause(attempt)
                    continue
                raise last_error from exc
            if completed.returncode == 0:
                return _json_from_text(completed.stdout)
            error_text = (completed.stderr or completed.stdout).strip()
            status = self._status_from_error(error_text)
            last_error = APIError(
                error_text or "kubectl request failed",
                status=status,
                body=error_text[:1000],
            )
            if attempt < self.retries and self._is_transient(status, error_text):
                self._retry_pause(attempt)
                continue
            raise last_error
        raise last_error or APIError("kubectl request failed")

    def probe_get(self, path: str) -> tuple[int | None, int]:
        """Probe a safe non-resource GET without retaining or printing its body."""
        self._validate_safe_get_path(path)
        if self.api_client is None:
            args = ["get", "--raw", path]
            self._validate_kubectl_args(args)
            command = self._kubectl_base() + args
            try:
                completed = subprocess.run(
                    command,
                    text=False,
                    capture_output=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return None, 0
            if completed.returncode == 0:
                return 200, len(completed.stdout)
            error_text = (completed.stderr or completed.stdout).decode(
                "utf-8", errors="replace"
            )
            return self._status_from_error(error_text), 0

        header_params = {"Accept": "*/*"}
        if self.impersonate_user:
            header_params["Impersonate-User"] = self.impersonate_user
        if self.impersonate_groups:
            header_params["Impersonate-Group"] = self.impersonate_groups[0]
        kwargs = {
            "auth_settings": ["BearerToken"],
            "header_params": header_params,
            "_return_http_data_only": True,
            "_preload_content": True,
            "_request_timeout": self.timeout,
        }
        if getattr(self, "_modern_call_api", False):
            kwargs["response_types_map"] = {200: "str"}
        else:
            kwargs["response_type"] = "str"
        try:
            result = self.api_client.call_api(path, "GET", **kwargs)
        except Exception as exc:
            return getattr(exc, "status", None), 0
        if isinstance(result, bytes):
            return 200, len(result)
        return 200, len(str(result or "").encode("utf-8"))

    def _official_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        method = method.upper()
        if method != "GET" and not (method == "POST" and path in SAFE_REVIEW_ENDPOINTS):
            raise ValueError(f"Refusing unsafe Kubernetes request: {method} {path}")
        if method == "GET":
            self._validate_safe_get_path(path)
        last_error: APIError | None = None
        for attempt in range(self.retries + 1):
            header_params = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            if self.impersonate_user:
                header_params["Impersonate-User"] = self.impersonate_user
            if self.impersonate_groups:
                header_params["Impersonate-Group"] = self.impersonate_groups[0]
            try:
                kwargs = {
                    "body": body,
                    "auth_settings": ["BearerToken"],
                    "header_params": header_params,
                    "_return_http_data_only": True,
                    "_preload_content": True,
                    "_request_timeout": self.timeout,
                }
                if getattr(self, "_modern_call_api", False):
                    kwargs["response_types_map"] = {200: "object", 201: "object"}
                else:
                    kwargs["response_type"] = "object"
                result = self.api_client.call_api(path, method, **kwargs)
                break
            except Exception as exc:
                status = getattr(exc, "status", None)
                body_text = str(getattr(exc, "body", "") or "")
                reason = str(getattr(exc, "reason", "") or exc)
                last_error = APIError(reason, status=status, body=body_text[:1000])
                if attempt < self.retries and self._is_transient(
                    status, f"{reason} {body_text}"
                ):
                    self._retry_pause(attempt)
                    continue
                raise last_error from exc
        else:
            raise last_error or APIError("Kubernetes API request failed")
        if isinstance(result, dict):
            return result
        if hasattr(result, "to_dict"):
            return result.to_dict()
        if isinstance(result, bytes):
            return _json_from_text(result.decode("utf-8", errors="replace"))
        if isinstance(result, str):
            return _json_from_text(result)
        raise APIError(f"Unsupported API response type: {type(result).__name__}")

    @staticmethod
    def _status_from_error(message: str) -> int | None:
        if "Unauthorized" in message:
            return 401
        if "Forbidden" in message:
            return 403
        if "NotFound" in message or "Not Found" in message or re.search(r"\b404\b", message):
            return 404
        if "Too Many Requests" in message or re.search(r"\b429\b", message):
            return 429
        if "ServiceUnavailable" in message or re.search(r"\b503\b", message):
            return 503
        if "Bad Gateway" in message or re.search(r"\b502\b", message):
            return 502
        if "Gateway Timeout" in message or re.search(r"\b504\b", message):
            return 504
        if "InternalError" in message or re.search(r"\b500\b", message):
            return 500
        return None

    @staticmethod
    def _is_transient(status: int | None, message: str) -> bool:
        try:
            normalized_status = int(status) if status is not None else None
        except (TypeError, ValueError):
            normalized_status = None
        if normalized_status in {429, 500, 502, 503, 504}:
            return True
        lowered = message.lower()
        return any(
            marker in lowered
            for marker in (
                "connection refused",
                "connection reset",
                "i/o timeout",
                "timed out",
                "tls handshake timeout",
                "temporary failure",
                "unexpected eof",
            )
        )

    @staticmethod
    def _retry_pause(attempt: int) -> None:
        time.sleep(min(0.25 * (2**attempt), 2.0))

    @staticmethod
    def _validate_kubectl_args(args: list[str]) -> None:
        if args == ["config", "view", "--minify", "--raw=false", "-o", "json"]:
            return
        if args[:2] == ["get", "--raw"] and len(args) == 3:
            K8sClient._validate_safe_get_path(args[2])
            return
        if args[:2] == ["create", "--raw"] and len(args) >= 3:
            if args[2] in SAFE_REVIEW_ENDPOINTS:
                return
        raise ValueError(f"Refusing unsafe kubectl operation: {' '.join(args)}")

    @staticmethod
    def _validate_safe_get_path(path: str) -> None:
        if not path.startswith("/"):
            raise ValueError("Kubernetes API path must start with /")
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc:
            raise ValueError("Kubernetes API path must be relative to the configured server")
        decoded_path = parsed.path
        for _ in range(3):
            newly_decoded = unquote(decoded_path)
            if newly_decoded == decoded_path:
                break
            decoded_path = newly_decoded
        decoded_path = decoded_path.rstrip("/")
        if re.search(
            r"/(?:pods|nodes|services)/[^/]+/(?:exec|attach|portforward|proxy)(?:/|$)",
            decoded_path,
            flags=re.IGNORECASE,
        ):
            raise ValueError(f"Refusing exec-like or proxy GET request: {path}")

    def get(self, path: str) -> dict[str, Any]:
        """Perform a GET request only."""
        if not path.startswith("/"):
            raise ValueError("Kubernetes API path must start with /")
        self._validate_safe_get_path(path)
        if self.api_client is not None:
            return self._official_request("GET", path)
        return self._kubectl_run(["get", "--raw", path])

    def list_items(
        self, path: str, *, page_limit: int = 500, max_pages: int = 100
    ) -> list[dict[str, Any]]:
        """Read a Kubernetes list endpoint with bounded pagination."""
        parts = urlsplit(path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query.setdefault("limit", str(page_limit))
        items: list[dict[str, Any]] = []
        for _ in range(max_pages):
            request_path = urlunsplit(
                ("", "", parts.path, urlencode(query), parts.fragment)
            )
            response = self.get(request_path)
            page_items = response.get("items") or []
            if not isinstance(page_items, list):
                raise APIError(f"List response items are not an array for {parts.path}")
            items.extend(item for item in page_items if isinstance(item, dict))
            metadata = response.get("metadata") or {}
            if not isinstance(metadata, dict):
                raise APIError(f"List response metadata is not an object for {parts.path}")
            continue_token = metadata.get("continue") or ""
            if not isinstance(continue_token, str):
                raise APIError(f"List continuation token is invalid for {parts.path}")
            if not continue_token:
                return items
            query["continue"] = continue_token
        raise APIError(f"Pagination exceeded {max_pages} pages for {parts.path}")

    def post_review(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST only to non-persisted self-review endpoints."""
        if path not in SAFE_REVIEW_ENDPOINTS:
            raise ValueError(f"Refusing POST to non-review endpoint: {path}")
        if self.api_client is not None:
            return self._official_request("POST", path, body)
        return self._kubectl_run(["create", "--raw", path, "-f", "-"], body)

    def context_info(self) -> dict[str, Any]:
        """Return sanitized local context data, never credentials."""
        namespace_path = Path(
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        )
        if self._in_cluster_available() and not self.kubeconfig and not self.context:
            namespace = ""
            try:
                namespace = namespace_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass
            return {
                "context": "in-cluster",
                "cluster": "in-cluster",
                "server": self.server or "from service environment",
                "namespace": namespace or "default",
                "source": "service-account mount",
            }

        if self.server and not self.kubeconfig:
            return {
                "context": self.context or "direct",
                "cluster": "",
                "server": self.server,
                "namespace": "default",
                "source": "arguments",
            }

        if not self._kubectl:
            return {
                "context": self.context or "",
                "cluster": "",
                "server": self.server or "",
                "namespace": "default",
                "source": "arguments",
            }
        try:
            data = self._kubectl_run(
                ["config", "view", "--minify", "--raw=false", "-o", "json"]
            )
            contexts = data.get("contexts") or []
            clusters = data.get("clusters") or []
            context_data = (contexts[0].get("context") or {}) if contexts else {}
            cluster_data = (clusters[0].get("cluster") or {}) if clusters else {}
            return {
                "context": self._source_context_name
                or data.get("current-context")
                or self.context
                or "",
                "cluster": context_data.get("cluster") or "",
                "server": self.server or cluster_data.get("server") or "",
                "namespace": context_data.get("namespace") or "default",
                "source": "kubeconfig",
            }
        except APIError:
            return {
                "context": self.context or "",
                "cluster": "",
                "server": self.server or "",
                "namespace": "default",
                "source": "arguments",
            }

    def local_bearer_token(self) -> str | None:
        """Return an already-present token for local JWT fallback, never for output."""
        if self.token:
            return self.token
        if self._in_cluster_available():
            try:
                return Path(
                    "/var/run/secrets/kubernetes.io/serviceaccount/token"
                ).read_text(encoding="utf-8").strip()
            except OSError:
                return None
        configuration = getattr(self.api_client, "configuration", None)
        authorization = (getattr(configuration, "api_key", {}) or {}).get(
            "authorization"
        )
        if not authorization:
            return None
        value = str(authorization)
        return value.removeprefix("Bearer ").strip() or None
