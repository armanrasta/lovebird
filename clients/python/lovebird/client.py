"""Sync client for lovebird-server evaluate API. Stdlib only — no httpx."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin


class LovebirdError(Exception):
    """HTTP or decode failure talking to lovebird-server."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class LovebirdClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8080", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        return self._request("GET", "health")

    def policies(self) -> dict[str, Any]:
        return self._request("GET", "api/v1/policies")

    def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "api/v1/authz/evaluate", request)

    def evaluate_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = self._request("POST", "api/v1/authz/evaluate/batch", requests)
        if not isinstance(out, list):
            raise LovebirdError("batch response was not a JSON array")
        return out

    def _request(self, method: str, path: str, body: Any | None = None) -> Any:
        url = urljoin(self.base_url, path)
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise LovebirdError(f"HTTP {e.code}: {detail}", status=e.code) from e
        except urllib.error.URLError as e:
            raise LovebirdError(f"request failed: {e}") from e
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise LovebirdError(f"invalid JSON: {e}") from e
