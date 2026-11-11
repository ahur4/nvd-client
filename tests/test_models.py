"""Parse real-shaped NVD JSON into pydantic models."""

import json
from datetime import date, datetime, timezone
from pathlib import Path

from nvd_client.models import CpeMatchResponse, CveListResponse, CveRecord

FIXTURE = Path(__file__).parent / "fixtures" / "cve_page.json"


def _page() -> CveListResponse:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return CveListResponse.model_validate(payload)


def test_cve_page_parses_envelope_and_record() -> None:
    page = _page()
    assert page.total_results == 42
    assert page.results_per_page == 1
    assert page.start_index == 0
    assert page.format == "NVD_CVE"
    assert page.version == "2.0"
    assert page.timestamp == datetime(2024, 6, 3, tzinfo=timezone.utc)
    assert len(page.cves) == 1

    cve = page.cves[0]
    assert isinstance(cve, CveRecord)
    assert cve.id == "CVE-2024-30078"
    assert cve.source_identifier == "secure@microsoft.com"
    assert cve.vuln_status == "Analyzed"
    assert cve.published == datetime(2024, 6, 1, 12, 0, 0)
    assert cve.published.tzinfo is None
    assert cve.last_modified == datetime(2024, 6, 2, 15, 30, 0, 123000, tzinfo=timezone.utc)
    assert cve.description() == "Windows Wi-Fi driver allows remote code execution."
    assert cve.description("es") is not None
    assert cve.description("fr") is None
    assert cve.cwe_ids == ["CWE-787", "NVD-CWE-noinfo"]
    assert cve.evaluator_comment == "NVD analysis note."
    assert cve.cisa_exploit_add == date(2024, 6, 11)
    assert cve.cisa_action_due == date(2024, 7, 2)
    assert cve.cisa_vulnerability_name is not None
    assert cve.cve_tags[0].tags == ["disputed"]


def test_cvss_metrics_v2_v30_v31_and_v40() -> None:
    metrics = _page().cves[0].metrics

    v2 = metrics.cvss_metric_v2[0]
    assert v2.source == "nvd@nist.gov"
    assert v2.type == "Primary"
    assert v2.cvss_data.version == "2.0"
    assert v2.cvss_data.vector_string == "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    assert v2.cvss_data.access_vector == "NETWORK"
    assert v2.cvss_data.base_score == 10.0
    assert v2.base_severity == "HIGH"
    assert v2.obtain_all_privilege is True
    assert v2.user_interaction_required is False

    v30 = metrics.cvss_metric_v30[0]
    assert v30.cvss_data.version == "3.0"
    assert v30.cvss_data.base_score == 7.5
    assert v30.cvss_data.attack_vector == "NETWORK"
    assert v30.exploitability_score == 3.9

    v31 = metrics.cvss_metric_v31[0]
    assert v31.cvss_data.version == "3.1"
    assert v31.cvss_data.vector_string.startswith("CVSS:3.1/")
    assert v31.cvss_data.base_severity == "HIGH"
    assert v31.cvss_data.scope == "UNCHANGED"
    assert v31.impact_score == 5.9

    v40 = metrics.cvss_metric_v40[0]
    assert v40.cvss_data.version == "4.0"
    assert v40.cvss_data.attack_vector == "ADJACENT"
    assert v40.cvss_data.attack_requirements == "NONE"
    assert v40.cvss_data.vuln_confidentiality_impact == "HIGH"
    assert v40.cvss_data.base_score == 8.8

    ssvc = metrics.ssvc_v203[0]
    assert ssvc.ssvc_data.role == "CISA Coordinator"
    assert ssvc.ssvc_data.version == "2.0.3"
    assert ssvc.ssvc_data.options[0]["exploitation"] == "poc"


def test_references_weaknesses_configurations_and_affected() -> None:
    cve = _page().cves[0]
    assert cve.references[0].tags == ["Vendor Advisory"]
    assert cve.references[1].tags == []
    assert cve.weaknesses[0].source == "nvd@nist.gov"

    node = cve.configurations[0].nodes[0]
    assert cve.configurations[0].operator == "AND"
    assert node.operator == "OR"
    match = node.cpe_match[0]
    assert match.vulnerable is True
    assert match.criteria.startswith("cpe:2.3:o:microsoft:windows_11")
    assert match.version_start_including == "10.0.22631"
    assert match.version_end_excluding == "10.0.22631.3737"

    assert cve.vendor_comments[0].organization == "Microsoft"
    product = cve.affected[0].affected_data[0]
    assert product.vendor == "Microsoft"
    assert product.platforms == ["x64"]
    assert product.program_routines[0].name == "wlan_ioctl"
    version = product.versions[0]
    assert version.status == "affected"
    assert version.less_than == "10.0.22631.3737"
    assert version.changes[0].status == "unaffected"


def test_minimal_record_and_dump_round_trip() -> None:
    payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-01-01T00:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-0001",
                    "published": "2020-01-01T00:00:00.000",
                    "lastModified": "2020-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Minimal."}],
                    "references": [{"url": "https://example.com/cve"}],
                }
            }
        ],
    }
    record = CveListResponse.model_validate(payload).cves[0]
    assert record.metrics.cvss_metric_v31 == []
    assert record.weaknesses == []
    assert record.configurations == []
    assert record.description() == "Minimal."

    snake = record.model_dump()
    assert snake["last_modified"]
    assert "lastModified" not in snake

    aliased = record.model_dump(by_alias=True, mode="json")
    assert aliased["lastModified"].startswith("2020-01-02")
    assert aliased["id"] == "CVE-2020-0001"
    again = CveRecord.model_validate(aliased)
    assert again == record

    encoded = record.model_dump_json(by_alias=True)
    assert isinstance(encoded, str)
    assert json.loads(encoded)["descriptions"][0]["value"] == "Minimal."


def test_unknown_fields_are_preserved() -> None:
    cve = _page().cves[0]
    assert cve.model_dump()["futureField"] == "kept"
    assert cve.model_dump(by_alias=True)["futureField"] == "kept"


def test_cpe_match_response() -> None:
    from .conftest import minimal_cpe_page

    page = CpeMatchResponse.model_validate(minimal_cpe_page())
    assert page.total_results == 1
    match = page.matches[0]
    assert match.status == "Active"
    assert match.version_end_excluding == "2.0"
    assert match.matches[0].cpe_name.endswith(":1.0:*:*:*:*:*:*:*")
    dumped = json.loads(page.model_dump_json(by_alias=True))
    assert dumped["matchStrings"][0]["matchString"]["matchCriteriaId"].startswith("11111111")
