# Quickstart

The examples below use the real API 2.0 methods. They look up one CVE, one page of CVEs published in a timezone-aware UTC window, the CPE match strings for that CVE, and the next pages of a date search.

Pass an API key from the environment when you have one. The same calls work without a key. See [Retries and rate limiting](retries.md) for the two NVD windows.

Use the client as a context manager, or call `close()`, so the connection pool is released.

## Look up one CVE

`get_cve_by_id` returns a `CveRecord`. A missing id raises `NvdNotFoundError`. An id that is not `CVE-YYYY-NNNN` with at least four digits in the sequence raises `InvalidCVEIDError` before any request is sent.

```python
import os

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(
    api_key=os.environ.get("NVD_API_KEY"),
    results_per_page=100,
)

with NvdApi(config=config) as api:
    record = api.get_cve_by_id("CVE-2024-30078")
    print(record.id, record.vuln_status)
    print(record.description())
    print(record.cwe_ids)
    for metric in record.metrics.cvss_metric_v31:
        data = metric.cvss_data
        print(metric.type, data.base_score, data.vector_string)
```

`description()` returns the English text, or `None` when that language is absent. `cwe_ids` is the weakness description values (`CWE-787`, `NVD-CWE-noinfo`, and similar).

## CVEs in a date range

`get_cve_by_date` returns one page, a `CveListResponse`. `total_results` is the size of the whole match. `cves` is only this page. A page with `total_results == 0` matched nothing. It is not an error.

NVD accepts a range of at most 120 days. The datetimes below are timezone-aware UTC, and seven days is inside that maximum.

```python
import os
from datetime import datetime, timedelta, timezone

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(api_key=os.environ.get("NVD_API_KEY"))
end = datetime.now(timezone.utc)
start = end - timedelta(days=7)

with NvdApi(config=config) as api:
    page = api.get_cve_by_date(
        publish_start_date=start,
        publish_end_date=end,
        per_page=50,
    )
    print(f"{len(page.cves)} of {page.total_results}")
    for cve in page.cves:
        print(cve.id, cve.published)
```

Exactly 120 days is accepted. One second more raises `InvalidParametersError` before a request is sent.

```python
from datetime import datetime, timedelta, timezone

start = datetime(2024, 1, 1, tzinfo=timezone.utc)
end = start + timedelta(days=120)
```

### How dates are sent

The client sends `YYYY-MM-DDTHH:MM:SS.sss+00:00`. `requests` percent-encodes the `+` as `%2B`, which is what NVD requires. Do not paste the timestamp into a URL by hand.

- An aware datetime, including one built with `zoneinfo.ZoneInfo`, is converted to UTC.
- A naive datetime is treated as UTC, not as the machine's local zone. `datetime.now()` is naive. Use `datetime.now(timezone.utc)`.
- Named zones on Windows need the `tzdata` package. `timezone.utc` does not.
- One end without the other, an end before the start, or a span longer than 120 days raises `InvalidParametersError` before any request is sent.
- A non-`datetime` value raises `InvalidDateFormatError`. If only one end is set, that check wins even when the value that is set is not a `datetime`.

`modify_start_date` and `modify_end_date` filter on `lastModified`. The query names are `lastModStartDate` and `lastModEndDate`. A publish range uses `pubStartDate` and `pubEndDate`. A publish range and a modify range may be sent in one call. Each pair still has to be complete and no longer than 120 days.

Timestamps in NVD responses are parsed as `datetime`. Values without an offset stay naive. Values with `Z` or a numeric offset are aware.

## CPE match

`get_cpes_by_cve` calls the CPE Match API (`/cpematch/2.0`) and returns a `CpeMatchResponse`. `matches` is the `CpeMatchString` objects on this page.

```python
import os

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(api_key=os.environ.get("NVD_API_KEY"))

with NvdApi(config=config) as api:
    found = api.get_cpes_by_cve("CVE-2024-30078", per_page=20)
    for item in found.matches:
        print(item.criteria, item.status, len(item.matches))
```

Two other CPE Match lookups hit the same endpoint:

| Method | Query parameter |
| --- | --- |
| `get_cpes_by_cve(cve_id)` | `cveId` |
| `get_cpes_by_criteria(criteria)` | `matchStringSearch` |
| `get_cpes_by_criteria_name_id(criteria_name_id)` | `matchCriteriaId` |

A blank `criteria` or `criteria_name_id` raises `InvalidParametersError` before the request. The default page size for these calls is `cpe_results_per_page` (500). NVD's maximum is 500.

`get_cve_by_cpe` goes the other way. It calls `/cves/2.0` with `cpeName` and returns CVEs whose applicability statement matches that CPE name. NVD requires a real part, vendor, product, and version in that name (`*` is not enough for those components). The client checks that the string is non-blank. It does not parse the CPE. The same publish and modify date arguments as `get_cve_by_date` are accepted.

```python
from nvd_client import NvdApi

with NvdApi() as api:
    windows = api.get_cve_by_cpe(
        "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
        per_page=20,
    )

for cve in windows.cves:
    print(cve.id)
```

## Paging with `offset`

Each call returns one page. There is no automatic pager. Advance `offset` by the page size. `start_index` is the offset NVD used, and `results_per_page` is the size of this response.

```python
import os
from datetime import datetime, timedelta, timezone

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(api_key=os.environ.get("NVD_API_KEY"))
end = datetime.now(timezone.utc)
start = end - timedelta(days=7)
offset = 0

with NvdApi(config=config) as api:
    while True:
        page = api.get_cve_by_date(
            per_page=200,
            offset=offset,
            publish_start_date=start,
            publish_end_date=end,
        )
        for cve in page.cves:
            print(cve.id)
        offset = page.start_index + page.results_per_page
        if not page.cves or offset >= page.total_results:
            break
```

`per_page=None` uses the config default (`results_per_page`, default 2000 for CVEs). `per_page` outside `1..2000` (CVE) or `1..500` (CPE match), or a negative `offset`, raises `InvalidParametersError`. A `bool` is rejected for both, because `bool` is a subclass of `int`.

The service sees `resultsPerPage` and `startIndex`.

## Query parameters

| Python argument | Query parameter | Used by |
| --- | --- | --- |
| `per_page` | `resultsPerPage` | every paged method |
| `offset` | `startIndex` | every paged method |
| `cve_id` on `get_cve_by_id` and `get_cpes_by_cve` | `cveId` | CVE and CPE Match |
| `cpe_name` | `cpeName` | `get_cve_by_cpe` |
| `publish_start_date`, `publish_end_date` | `pubStartDate`, `pubEndDate` | `get_cve_by_date`, `get_cve_by_cpe` |
| `modify_start_date`, `modify_end_date` | `lastModStartDate`, `lastModEndDate` | `get_cve_by_date`, `get_cve_by_cpe` |
| `criteria` | `matchStringSearch` | `get_cpes_by_criteria` |
| `criteria_name_id` | `matchCriteriaId` | `get_cpes_by_criteria_name_id` |

`get_all_cves` sends only the page parameters.

A per-call `proxy` overrides the client proxy for that request. See [Configuration](configuration.md).
