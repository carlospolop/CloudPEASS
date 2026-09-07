"""Small, defensive HTTP helpers shared by CloudPEASS enumerators."""

from __future__ import annotations

import email.utils
import random
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, Optional, Sequence
from urllib.parse import urlparse

import requests


class ReadOnlyHttpClient:
    """HTTP client that can never issue a state-changing request.

    Cloud enumeration routinely encounters throttling, transient gateway errors,
    malformed error bodies, and broken pagination links.  Keeping that handling
    here makes each PEASS both safer and easier to audit.
    """

    RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})

    def __init__(
        self,
        *,
        allowed_hosts: Optional[Iterable[str]] = None,
        max_retries: int = 4,
        timeout: Sequence[float] = (10, 45),
        session: Optional[requests.Session] = None,
        sleep=time.sleep,
    ):
        self.allowed_hosts = {
            host.lower().rstrip(".") for host in (allowed_hosts or [])
        }
        self.max_retries = max(0, int(max_retries))
        self.timeout = tuple(timeout)
        self.session = session
        self._local = threading.local()
        self._sleep = sleep

    def _session(self):
        """Return an isolated session per worker unless a test/session is injected."""

        if self.session is not None:
            return self.session
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update({"User-Agent": "CloudPEASS/read-only"})
            self._local.session = session
        return session

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError(f"Invalid or non-HTTPS API URL: {url!r}")
        hostname = parsed.hostname.lower().rstrip(".")
        if self.allowed_hosts and hostname not in self.allowed_hosts:
            raise ValueError(f"Refusing to send credentials to unexpected host: {hostname}")

    @staticmethod
    def _retry_delay(response: requests.Response, attempt: int) -> float:
        retry_after_ms = response.headers.get("x-ms-retry-after-ms")
        if retry_after_ms:
            try:
                return min(max(float(retry_after_ms) / 1000.0, 0.0), 120.0)
            except ValueError:
                pass
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(max(float(header), 0.0), 120.0)
            except ValueError:
                try:
                    retry_at = email.utils.parsedate_to_datetime(header)
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=timezone.utc)
                    return min(
                        max((retry_at - datetime.now(timezone.utc)).total_seconds(), 0.0),
                        120.0,
                    )
                except (TypeError, ValueError, OverflowError):
                    pass
        return min((2**attempt) + random.uniform(0, 0.25), 30.0)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError(f"ReadOnlyHttpClient refuses HTTP method {method}")
        self._validate_url(url)

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._session().request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    raise
                self._sleep(min((2**attempt) + random.uniform(0, 0.25), 30.0))
                continue

            if response.status_code not in self.RETRYABLE_STATUSES:
                return response
            if attempt >= self.max_retries:
                return response
            self._sleep(self._retry_delay(response, attempt))

        if last_error:
            raise last_error
        raise RuntimeError("HTTP request retry loop ended unexpectedly")

    def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        return self.request("GET", url, headers=headers, params=params)

    def iter_pages(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        next_keys: Sequence[str] = ("nextLink", "@odata.nextLink"),
        max_pages: int = 1000,
    ) -> Iterator[requests.Response]:
        """Yield paginated responses without following loops forever."""

        seen = set()
        next_url = url
        next_params = params
        for _ in range(max_pages):
            if next_url in seen:
                raise RuntimeError(f"Pagination loop detected at {next_url}")
            seen.add(next_url)
            response = self.get(next_url, headers=headers, params=next_params)
            yield response
            if response.status_code < 200 or response.status_code >= 300:
                return
            try:
                data = response.json()
            except ValueError:
                return
            next_url = next((data.get(key) for key in next_keys if data.get(key)), None)
            if not next_url:
                return
            next_params = None
        raise RuntimeError(f"Pagination exceeded the {max_pages}-page safety limit")
