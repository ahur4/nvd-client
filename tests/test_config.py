"""Configuration defaults, validation, and what the client sends."""

from datetime import datetime, timedelta, timezone

import pytest
import requests

from nvd_client import NvdApi, NvdConfig
from nvd_client.config import (
    RATE_LIMIT_REQUESTS_WITH_KEY,
    RATE_LIMIT_REQUESTS_WITHOUT_KEY,
    RATE_LIMIT_WINDOW_SECONDS,
)
from nvd_client.version import __version__

from .conftest import FakeResponse, attach, empty_cve_page, make_client


def test_delay_follows_nvd_windows() -> None:
    without_key = NvdConfig()
    with_key = NvdConfig(api_key="secret")
    assert without_key.effective_rate_limit_delay == (
        RATE_LIMIT_WINDOW_SECONDS / RATE_LIMIT_REQUESTS_WITHOUT_KEY
    )
    assert with_key.effective_rate_limit_delay == (
        RATE_LIMIT_WINDOW_SECONDS / RATE_LIMIT_REQUESTS_WITH_KEY
    )
    assert NvdConfig(rate_limit_delay=2.5).effective_rate_limit_delay == 2.5
    assert NvdConfig(api_key="secret", rate_limit_delay=0).effective_rate_limit_delay == 0


def test_blank_api_key_is_absent() -> None:
    config = NvdConfig(api_key="  ")
    assert config.api_key is None
    assert config.effective_rate_limit_delay == 6.0


def test_default_user_agent_identifies_the_library() -> None:
    config = NvdConfig()
    assert __version__ in config.user_agent
    assert config.user_agent.startswith("nvd-client/")
    assert NvdConfig(user_agent="  research/1 ").user_agent == "research/1"


def test_invalid_config_is_rejected() -> None:
    with pytest.raises(ValueError):
        NvdConfig(base_url="ftp://example.com")
    with pytest.raises(ValueError):
        NvdConfig(timeout=0)
    with pytest.raises(ValueError):
        NvdConfig(timeout=(1, 0))
    with pytest.raises(ValueError):
        NvdConfig(results_per_page=2001)
    with pytest.raises(ValueError):
        NvdConfig(cpe_results_per_page=0)
    with pytest.raises(ValueError):
        NvdConfig(max_retries=-1)
    with pytest.raises(ValueError):
        NvdConfig(rate_limit_delay=-1)
    with pytest.raises(ValueError):
        NvdConfig(backoff_factor=-0.1)


def test_constructor_keeps_positional_api_key_and_proxy() -> None:
    api = NvdApi("top-secret", "http://proxy.example:8080", config=NvdConfig(timeout=12))
    assert api.config.api_key == "top-secret"
    assert api.config.proxy == "http://proxy.example:8080"
    assert api.config.timeout == 12
    assert "top-secret" not in repr(api)
    assert "api_key=set" in repr(api)


def test_request_uses_config_headers_timeout_and_page_size() -> None:
    api = make_client(
        api_key="abc",
        timeout=(3.0, 15.0),
        results_per_page=25,
        user_agent="lab-scanner/2",
        base_url="https://nvd.example/rest/json/",
    )
    session = attach(api, [FakeResponse(200, empty_cve_page())])
    page = api.get_all_cves()
    assert page.total_results == 0
    call = session.calls[0]
    assert call["url"] == "https://nvd.example/rest/json/cves/2.0"
    assert "?" not in call["url"]
    assert call["params"] == {"resultsPerPage": 25, "startIndex": 0}
    assert call["timeout"] == (3.0, 15.0)
    assert session.headers["User-Agent"] == "lab-scanner/2"
    assert session.headers["apiKey"] == "abc"
    assert "abc" not in call["url"]


def test_per_call_proxy_overrides_the_client_proxy() -> None:
    api = NvdApi(
        proxy="http://default.example:8080",
        config=NvdConfig(rate_limit_delay=0, max_retries=0),
    )
    session = attach(api, [FakeResponse(200, empty_cve_page())])
    api.get_all_cves(proxy="socks5h://override.example:1080")
    assert session.calls[0]["proxies"] == {
        "http": "socks5h://override.example:1080",
        "https": "socks5h://override.example:1080",
    }


def test_dates_are_utc_and_left_for_requests_to_encode() -> None:
    api = make_client()
    session = attach(api, [FakeResponse(200, empty_cve_page())])
    start = datetime(2024, 1, 1, 1, 30, tzinfo=timezone(timedelta(hours=1)))
    end = datetime(2024, 1, 2)
    api.get_cve_by_date(publish_start_date=start, publish_end_date=end, per_page=10)
    params = session.calls[0]["params"]
    assert params["pubStartDate"] == "2024-01-01T00:30:00.000+00:00"
    assert params["pubEndDate"] == "2024-01-02T00:00:00.000+00:00"
    assert params["resultsPerPage"] == 10

    prepared = requests.Request(
        "GET",
        session.calls[0]["url"],
        params=params,
    ).prepare()
    assert prepared.url is not None
    assert "pubStartDate=2024-01-01T00%3A30%3A00.000%2B00%3A00" in prepared.url
    assert "%2B" in prepared.url


def test_context_manager_closes_the_session() -> None:
    api = make_client()
    closed: list[bool] = []
    api._session.close = lambda: closed.append(True)  # type: ignore[method-assign]
    with api:
        assert api.config.base_url.startswith("https://services.nvd.nist.gov")
    assert closed == [True]
