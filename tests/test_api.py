"""Query building and the typed return contract. HTTP is mocked."""

from datetime import datetime, timedelta, timezone

import pytest

from nvd_client import (
    CveRecord,
    InvalidCVEIDError,
    InvalidDateFormatError,
    InvalidParametersError,
    NvdNotFoundError,
    NvdResponseError,
)
from nvd_client.models import CpeMatchResponse

from .conftest import (
    FakeResponse,
    attach,
    empty_cve_page,
    make_client,
    minimal_cpe_page,
    minimal_cve_page,
)


def test_get_cve_by_id_returns_the_record() -> None:
    api = make_client()
    attach(api, [FakeResponse(200, minimal_cve_page("CVE-2024-30078"))])
    record = api.get_cve_by_id("CVE-2024-30078")
    assert isinstance(record, CveRecord)
    assert record.id == "CVE-2024-30078"
    assert record.description() == "Example vulnerability."


def test_get_cve_by_id_rejects_a_bad_id_without_calling_http() -> None:
    api = make_client()
    session = attach(api, [])
    with pytest.raises(InvalidCVEIDError):
        api.get_cve_by_id("cve-2024-1")
    assert session.calls == []


def test_missing_cve_is_an_error_not_an_empty_result() -> None:
    api = make_client()
    attach(api, [FakeResponse(200, empty_cve_page())])
    with pytest.raises(NvdNotFoundError):
        api.get_cve_by_id("CVE-2024-0001")


def test_http_404_is_not_found() -> None:
    api = make_client(max_retries=3)
    session = attach(api, [FakeResponse(404, text="no such cve")])
    with pytest.raises(NvdNotFoundError) as caught:
        api.get_cve_by_id("CVE-2024-0001")
    assert caught.value.status_code == 404
    assert len(session.calls) == 1


def test_empty_collection_is_a_page() -> None:
    api = make_client()
    attach(api, [FakeResponse(200, empty_cve_page())])
    page = api.get_all_cves()
    assert page.total_results == 0
    assert page.cves == []


def test_invalid_document_raises_response_error() -> None:
    api = make_client()
    attach(api, [FakeResponse(200, {"resultsPerPage": 0})])
    with pytest.raises(NvdResponseError):
        api.get_all_cves()


def test_non_json_body_raises_response_error() -> None:
    api = make_client()
    attach(api, [FakeResponse(200, text="<html>nope</html>")])
    with pytest.raises(NvdResponseError):
        api.get_all_cves()


def test_page_size_and_offset_limits() -> None:
    api = make_client()
    session = attach(api, [])
    with pytest.raises(InvalidParametersError):
        api.get_all_cves(per_page=2001)
    with pytest.raises(InvalidParametersError):
        api.get_all_cves(per_page=0)
    with pytest.raises(InvalidParametersError):
        api.get_all_cves(offset=-1)
    with pytest.raises(InvalidParametersError):
        api.get_cpes_by_cve("CVE-2024-0001", per_page=501)
    assert session.calls == []


def test_date_rules() -> None:
    api = make_client()
    session = attach(
        api,
        [FakeResponse(200, empty_cve_page()), FakeResponse(200, empty_cve_page())],
    )
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(InvalidParametersError):
        api.get_cve_by_date(publish_start_date=start)
    with pytest.raises(InvalidDateFormatError):
        api.get_cve_by_date(
            publish_start_date="2024-01-01",  # type: ignore[arg-type]
            publish_end_date="2024-01-02",  # type: ignore[arg-type]
        )
    with pytest.raises(InvalidParametersError):
        api.get_cve_by_date(
            publish_start_date=start,
            publish_end_date=start - timedelta(seconds=1),
        )
    with pytest.raises(InvalidParametersError):
        api.get_cve_by_date(
            modify_start_date=start,
            modify_end_date=start + timedelta(days=120, seconds=1),
        )

    api.get_cve_by_date(
        publish_start_date=start,
        publish_end_date=start + timedelta(days=120),
    )
    expected_end = (start + timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    assert session.calls[0]["params"]["pubStartDate"].endswith("+00:00")
    assert session.calls[0]["params"]["pubEndDate"] == expected_end

    api.get_cve_by_date(
        modify_start_date=start,
        modify_end_date=start + timedelta(days=1),
    )
    modify_params = session.calls[1]["params"]
    assert modify_params["lastModStartDate"] == "2024-01-01T00:00:00.000+00:00"
    assert modify_params["lastModEndDate"] == "2024-01-02T00:00:00.000+00:00"
    assert "pubStartDate" not in modify_params


def test_cpe_queries_hit_the_match_api() -> None:
    api = make_client(cpe_results_per_page=20)
    session = attach(
        api,
        [
            FakeResponse(200, minimal_cpe_page()),
            FakeResponse(200, minimal_cpe_page()),
            FakeResponse(200, minimal_cpe_page()),
        ],
    )
    by_cve = api.get_cpes_by_cve("CVE-2024-30078")
    by_criteria = api.get_cpes_by_criteria("cpe:2.3:a:example:app")
    by_id = api.get_cpes_by_criteria_name_id("11111111-1111-1111-1111-111111111111")
    assert isinstance(by_cve, CpeMatchResponse)
    assert by_cve.matches[0].match_criteria_id.startswith("11111111")
    assert all(call["url"].endswith("/cpematch/2.0") for call in session.calls)
    assert session.calls[0]["params"]["cveId"] == "CVE-2024-30078"
    assert session.calls[0]["params"]["resultsPerPage"] == 20
    assert session.calls[1]["params"]["matchStringSearch"] == "cpe:2.3:a:example:app"
    assert session.calls[2]["params"]["matchCriteriaId"].startswith("11111111")
    assert by_criteria.total_results == 1
    assert by_id.matches[0].status == "Active"

    with pytest.raises(InvalidParametersError):
        api.get_cve_by_cpe("  ")
    with pytest.raises(InvalidParametersError):
        api.get_cpes_by_criteria("")


def test_cve_by_cpe_uses_the_cve_endpoint() -> None:
    api = make_client()
    session = attach(api, [FakeResponse(200, empty_cve_page())])
    page = api.get_cve_by_cpe(
        "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
        per_page=5,
        offset=10,
    )
    assert page.cves == []
    call = session.calls[0]
    assert call["url"].endswith("/cves/2.0")
    assert call["params"]["cpeName"] == "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
    assert call["params"]["resultsPerPage"] == 5
    assert call["params"]["startIndex"] == 10
