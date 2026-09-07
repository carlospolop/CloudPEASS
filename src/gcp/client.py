"""Small, read-only Google Cloud REST client used by GCPPEASS.

The client intentionally accepts only GET requests and a narrow set of POST
operations whose APIs are read-only.  Keeping this guard in the transport
layer makes it much harder for an enumeration feature to accidentally mutate
the target environment.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterator, Optional
from urllib.parse import urlparse

import requests
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import AuthorizedSession


RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
READ_ONLY_POST_SUFFIXES = (
    ":getIamPolicy",
    ":search",
    ":testIamPermissions",
    "/getIamPolicy",
    "/testIamPermissions",
    "/iam/testPermissions",
    "/permissions:queryTestablePermissions",
)


@dataclass
class GCPApiError(Exception):
    """An HTTP or transport error with enough context for useful fallbacks."""

    status: Optional[int]
    message: str
    url: str
    reason: str = ""

    @property
    def category(self) -> str:
        if self.status is not None:
            return f"HTTP {self.status}"
        if self.reason.startswith("auth:"):
            return "authentication"
        return "network"

    def __str__(self) -> str:
        prefix = f"{self.category} error" if self.status is None else self.category
        message = " ".join(self.message.split())
        if len(message) > 300:
            message = message[:297] + "..."
        return f"{prefix}: {message}"


class GCPReadOnlyClient:
    """Thread-local authorized sessions with retry and pagination support."""

    def __init__(
        self,
        credentials,
        billing_project: str = "",
        proxy: str = "",
        timeout: float = 20.0,
        retries: int = 3,
        verify_tls: bool = True,
        max_concurrency: int = 5,
    ) -> None:
        self.credentials = credentials
        self.billing_project = (billing_project or "").strip()
        self.proxy = self._normalize_proxy(proxy)
        self.timeout = max(1.0, float(timeout))
        self.retries = max(0, int(retries))
        self.verify_tls = verify_tls
        self._local = threading.local()
        self._request_slots = threading.BoundedSemaphore(max(1, int(max_concurrency)))

    @staticmethod
    def _normalize_proxy(proxy: str) -> str:
        proxy = (proxy or "").strip()
        if not proxy:
            return ""
        candidate = proxy if "://" in proxy else f"http://{proxy}"
        parsed = urlparse(candidate)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(
                "Proxy must include a valid numeric port, for example 127.0.0.1:8080"
            ) from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or not port:
            raise ValueError("Proxy must include a host and port, for example 127.0.0.1:8080")
        return candidate

    def _session(self) -> AuthorizedSession:
        session = getattr(self._local, "session", None)
        if session is None:
            session = AuthorizedSession(self.credentials)
            session.headers.update({"User-Agent": "CloudPEASS-GCP/read-only"})
            if self.proxy:
                session.proxies.update({"http": self.proxy, "https": self.proxy})
            self._local.session = session
        return session

    @staticmethod
    def _assert_read_only(method: str, url: str) -> None:
        method = method.upper()
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not (
            host == "googleapis.com" or host.endswith(".googleapis.com")
        ):
            raise ValueError(f"Blocked non-Google or non-HTTPS GCP request: {method} {url}")
        if method == "GET":
            return
        path = parsed.path
        if method == "POST" and any(path.endswith(suffix) for suffix in READ_ONLY_POST_SUFFIXES):
            return
        raise ValueError(f"Blocked non-read-only GCP request: {method} {url}")

    @staticmethod
    def _retry_delay(value: str, attempt: int) -> float:
        try:
            return min(max(float(value), 0.0), 30.0)
        except (TypeError, ValueError):
            pass
        if value:
            try:
                retry_at = parsedate_to_datetime(value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return min(max((retry_at - datetime.now(timezone.utc)).total_seconds(), 0.0), 30.0)
            except (TypeError, ValueError, OverflowError):
                pass
        return min((2**attempt) + random.random(), 15.0)

    @staticmethod
    def _error_from_response(response: requests.Response) -> GCPApiError:
        message = response.text.strip() or response.reason or "request failed"
        reason = ""
        try:
            payload = response.json()
            error = payload.get("error", payload) if isinstance(payload, dict) else {}
            if isinstance(error, dict):
                message = error.get("message") or message
                details = error.get("details") or []
                if details and isinstance(details[0], dict):
                    reason = details[0].get("reason", "")
                if not reason:
                    reason = error.get("status", "")
        except (ValueError, TypeError):
            pass
        return GCPApiError(response.status_code, message, response.url, reason)

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Perform an allowlisted read-only request and return a JSON object."""

        method = method.upper()
        self._assert_read_only(method, url)
        request_headers = dict(headers or {})
        if self.billing_project:
            request_headers.setdefault("X-Goog-User-Project", self.billing_project)

        last_error: Optional[GCPApiError] = None
        for attempt in range(self.retries + 1):
            try:
                with self._request_slots:
                    response = self._session().request(
                        method,
                        url,
                        params=params,
                        json=json,
                        headers=request_headers,
                        timeout=timeout or self.timeout,
                        verify=self.verify_tls,
                    )
            except requests.RequestException as exc:
                last_error = GCPApiError(None, str(exc), url, type(exc).__name__)
                if attempt >= self.retries:
                    raise last_error from exc
            except GoogleAuthError as exc:
                last_error = GCPApiError(None, str(exc), url, f"auth:{type(exc).__name__}")
                if attempt >= self.retries:
                    raise last_error from exc
            else:
                if 200 <= response.status_code < 300:
                    if not response.content:
                        return {}
                    try:
                        payload = response.json()
                    except ValueError as exc:
                        raise GCPApiError(
                            response.status_code,
                            "API returned a non-JSON response",
                            response.url,
                            "invalidResponse",
                        ) from exc
                    if not isinstance(payload, dict):
                        raise GCPApiError(
                            response.status_code,
                            "API returned an unexpected JSON value",
                            response.url,
                            "invalidResponse",
                        )
                    return payload

                last_error = self._error_from_response(response)
                if response.status_code not in RETRYABLE_STATUS_CODES or attempt >= self.retries:
                    raise last_error

                time.sleep(self._retry_delay(response.headers.get("Retry-After", ""), attempt))

        # The loop always returns or raises. This keeps type checkers honest.
        raise last_error or GCPApiError(None, "request failed", url)

    def iter_pages(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        token_in_body: bool = False,
    ) -> Iterator[Dict[str, Any]]:
        """Yield API pages while preserving the caller's original arguments."""

        page_params = dict(params or {})
        page_json = dict(json or {})
        while True:
            page = self.request(method, url, params=page_params, json=page_json or None)
            yield page
            token = page.get("nextPageToken")
            if not token:
                break
            if token_in_body:
                page_json["pageToken"] = token
            else:
                page_params["pageToken"] = token
