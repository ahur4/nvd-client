"""Retries, Retry-After, and the spacing between requests."""

import time
from email.utils import formatdate

import pytest
import requests

from nvd_client import NvdApi, NvdApiError, NvdConfig, NvdRateLimitError

from .conftest import FakeResponse, attach, empty_cve_page, make_client


def _ok() -> FakeResponse:
    return FakeResponse(200, empty_cve_page())


def test_retries_forbidden_and_then_succeeds() -> None:
    api = make_client(max_retries=2, backoff_factor=1)
    slept: list[float] = []
    api._sleep = slept.append
    session = attach(
        api,
        [FakeResponse(403, text="Request forbidden by administrative rules."), _ok()],
    )
    page = api.get_all_cves()
    assert page.total_results == 0
    assert len(session.calls) == 2
    assert slept == [1.0]


def test_retry_after_replaces_exponential_backoff() -> None:
    api = make_client(max_retries=2, backoff_factor=1)
    slept: list[float] = []
    api._sleep = slept.append
    waiting = FakeResponse(429, text="slow down", headers={"Retry-After": "12"})
    attach(api, [waiting, _ok()])
    api.get_all_cves()
    assert slept == [12.0]


def test_http_date_retry_after_is_honored() -> None:
    api = make_client(max_retries=1, backoff_factor=1)
    slept: list[float] = []
    api._sleep = slept.append
    header = formatdate(time.time() + 5, usegmt=True)
    attach(api, [FakeResponse(503, headers={"Retry-After": header}, text="busy"), _ok()])
    api.get_all_cves()
    assert slept[0] == pytest.approx(5, abs=2)


def test_service_errors_use_exponential_backoff() -> None:
    api = make_client(max_retries=3, backoff_factor=1, max_backoff=3)
    slept: list[float] = []
    api._sleep = slept.append
    attach(
        api,
        [
            FakeResponse(503, text="unavailable"),
            FakeResponse(502, text="bad gateway"),
            FakeResponse(500, text="error"),
            _ok(),
        ],
    )
    api.get_all_cves()
    assert slept == [1.0, 2.0, 3.0]


def test_exhausted_rate_limit_raises() -> None:
    api = make_client(max_retries=1, backoff_factor=0)
    session = attach(
        api,
        [FakeResponse(403, text="slow down"), FakeResponse(429, text="still slow")],
    )
    with pytest.raises(NvdRateLimitError) as caught:
        api.get_all_cves()
    assert caught.value.status_code == 429
    assert len(session.calls) == 2


def test_invalid_api_key_is_not_retried() -> None:
    api = make_client(max_retries=4, api_key="not-a-real-key")
    session = attach(
        api,
        [FakeResponse(403, text="Invalid apiKey.", headers={"message": "Invalid apiKey"})],
    )
    with pytest.raises(NvdApiError) as caught:
        api.get_all_cves()
    assert not isinstance(caught.value, NvdRateLimitError)
    assert caught.value.status_code == 403
    assert len(session.calls) == 1


def test_client_errors_are_not_retried() -> None:
    api = make_client(max_retries=3)
    session = attach(api, [FakeResponse(400, text="resultsPerPage parameter out of range")])
    with pytest.raises(NvdApiError) as caught:
        api.get_all_cves()
    assert caught.value.status_code == 400
    assert len(session.calls) == 1


def test_connection_errors_are_retried() -> None:
    api = make_client(max_retries=1, backoff_factor=0.5)
    slept: list[float] = []
    api._sleep = slept.append
    session = attach(api, [requests.ConnectionError("reset"), _ok()])
    assert api.get_all_cves().cves == []
    assert len(session.calls) == 2
    assert slept == [0.5]


def test_connection_error_after_retries_raises() -> None:
    api = make_client(max_retries=0)
    attach(api, [requests.Timeout("timed out")])
    with pytest.raises(NvdApiError, match="timed out"):
        api.get_all_cves()


def test_requests_are_spaced_by_the_configured_delay() -> None:
    api = make_client(rate_limit_delay=6, max_retries=0)
    clock = {"now": 0.0}
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["now"] += seconds

    api._sleep = sleep
    api._monotonic = lambda: clock["now"]
    attach(api, [_ok(), _ok(), _ok()])
    api.get_all_cves()
    api.get_all_cves()
    api.get_all_cves()
    assert slept == [6.0, 6.0]


def test_api_key_default_spacing_is_under_the_higher_limit() -> None:
    api = NvdApi(config=NvdConfig(api_key="abc", max_retries=0))
    clock = {"now": 0.0}
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["now"] += seconds

    api._sleep = sleep
    api._monotonic = lambda: clock["now"]
    attach(api, [_ok(), _ok()])
    api.get_all_cves()
    api.get_all_cves()
    assert slept == [0.6]
