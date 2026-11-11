"""Shared fixtures. HTTP is always fake; nothing here contacts NVD."""

from __future__ import annotations

import json
from typing import Any

from nvd_client import NvdApi, NvdConfig


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: Any = None,
        headers: dict[str, str] | None = None,
        text: str | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        if text is not None:
            self.text = text
        elif payload is not None:
            self.text = json.dumps(payload)
        else:
            self.text = ""

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("response is not JSON")
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self.headers: dict[str, str] = {}
        self.closed = False

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if not self._responses:
            raise AssertionError(f"unexpected request to {url}")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        self.closed = True


def minimal_cve_page(cve_id: str = "CVE-2024-0001", total: int | None = None) -> dict[str, Any]:
    vulnerabilities = [
        {
            "cve": {
                "id": cve_id,
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Example vulnerability."}],
                "references": [{"url": "https://example.com/advisory"}],
            }
        }
    ]
    count = len(vulnerabilities) if total is None else total
    return {
        "resultsPerPage": len(vulnerabilities),
        "startIndex": 0,
        "totalResults": count,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-01-03T00:00:00.000",
        "vulnerabilities": vulnerabilities,
    }


def empty_cve_page() -> dict[str, Any]:
    return {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-01-03T00:00:00.000",
        "vulnerabilities": [],
    }


def minimal_cpe_page() -> dict[str, Any]:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CPEMatchString",
        "version": "2.0",
        "timestamp": "2024-01-03T00:00:00.000",
        "matchStrings": [
            {
                "matchString": {
                    "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
                    "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
                    "created": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "status": "Active",
                    "versionEndExcluding": "2.0",
                    "matches": [
                        {
                            "cpeName": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*",
                            "cpeNameId": "22222222-2222-2222-2222-222222222222",
                        }
                    ],
                }
            }
        ],
    }


def make_client(**overrides: Any) -> NvdApi:
    config_args: dict[str, Any] = {"rate_limit_delay": 0, "max_retries": 0, "backoff_factor": 1}
    config_args.update(overrides)
    return NvdApi(config=NvdConfig(**config_args))


def attach(api: NvdApi, responses: list[FakeResponse | Exception]) -> FakeSession:
    session = FakeSession(responses)
    api._session = session  # type: ignore[assignment]
    return session
