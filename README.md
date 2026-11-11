# NVD API Client

[![PyPI](https://img.shields.io/pypi/v/nvd-client)](https://pypi.org/project/nvd-client/)
[![CI](https://github.com/ahur4/nvd-client/actions/workflows/ci.yml/badge.svg)](https://github.com/ahur4/nvd-client/actions/workflows/ci.yml)

A typed Python client for the National Vulnerability Database REST API 2.0.
It fetches CVE records and CPE match strings for vulnerability research and
defense. It does not change anything at NVD.

The code in this repository is version 0.2.0. That version is not published
to PyPI yet. `pip install nvd-client` still installs the 0.1.x release, which
returns raw dictionaries and does not match the examples below. Install from
a checkout of this version until it is released:

```sh
pip install .
```

Development tools (pytest, ruff, mypy):

```sh
pip install -e ".[dev]"
```

SOCKS proxies need the optional extra. HTTP and HTTPS proxies work without it.

```sh
pip install -e ".[socks]"
```

Python 3.10 or newer is required.

## Return contract

Collection calls return a pydantic model, never a `dict` and never `None`.

| Method | Returns |
| --- | --- |
| `get_all_cves` | `CveListResponse` |
| `get_cve_by_date` | `CveListResponse` |
| `get_cve_by_cpe` | `CveListResponse` |
| `get_cve_by_id` | `CveRecord` |
| `get_cpes_by_cve` | `CpeMatchResponse` |
| `get_cpes_by_criteria` | `CpeMatchResponse` |
| `get_cpes_by_criteria_name_id` | `CpeMatchResponse` |

`CveListResponse.cves` is the list of `CveRecord` objects on this page.
`total_results` is the size of the whole match. An empty match is a normal
page: `total_results == 0` and `cves == []`. `get_cve_by_id` raises
`NvdNotFoundError` instead of returning that empty page.

`CpeMatchResponse.matches` is the list of match strings on the page.

Failed requests raise. They do not look like an empty fetch.

| Situation | Exception |
| --- | --- |
| Bad CVE id | `InvalidCVEIDError` |
| Date or page arguments NVD will reject | `InvalidDateFormatError` or `InvalidParametersError` |
| HTTP 404, or a CVE id NVD does not have | `NvdNotFoundError` |
| HTTP 403 or 429 after retries | `NvdRateLimitError` |
| Other HTTP errors and connection failures | `NvdApiError` |
| Body is not the expected document | `NvdResponseError` |

All of those inherit from `NvdClientError`.

### Serialization

Models use snake_case attributes. The NVD names are aliases.

```python
record.model_dump()  # snake_case, Python values
record.model_dump(by_alias=True)  # NVD camelCase
record.model_dump(by_alias=True, mode="json", exclude_none=True)
record.model_dump_json(by_alias=True, indent=2)
```

`mode="json"` and `model_dump_json()` turn datetimes into ISO strings.
Unknown JSON keys are kept and appear in `model_dump()`, so a field NVD adds
later is not dropped. Missing metric groups are empty lists.

Nested types (`LangString`, `Reference`, `Metrics`, `CvssMetricV2`,
`CvssMetricV30`, `CvssMetricV31`, `CvssMetricV40`, `Weakness`,
`Configuration`, `CpeMatch`, `Affected`, and the CPE match types) live in
`nvd_client.models`.

`CveRecord` fields:

| Attribute | NVD name | Notes |
| --- | --- | --- |
| `id` | `id` | `CVE-YYYY-NNNN` |
| `source_identifier` | `sourceIdentifier` | |
| `vuln_status` | `vulnStatus` | |
| `published` | `published` | `datetime` |
| `last_modified` | `lastModified` | `datetime` |
| `descriptions` | `descriptions` | `LangString` (`lang`, `value`) |
| `references` | `references` | `url`, optional `source` and `tags` |
| `metrics` | `metrics` | CVSS v2, v3.0, v3.1, v4.0, and SSVC |
| `weaknesses` | `weaknesses` | CWE text is in `description` |
| `configurations` | `configurations` | CPE applicability tree |
| `affected` | `affected` | vendor, product, versions |
| `cve_tags` | `cveTags` | for example `disputed` |
| `vendor_comments` | `vendorComments` | |
| `evaluator_comment` | `evaluatorComment` | optional |
| `evaluator_solution` | `evaluatorSolution` | optional |
| `evaluator_impact` | `evaluatorImpact` | optional |
| `cisa_exploit_add` | `cisaExploitAdd` | `date` when the CVE is in KEV |
| `cisa_action_due` | `cisaActionDue` | `date` |
| `cisa_required_action` | `cisaRequiredAction` | |
| `cisa_vulnerability_name` | `cisaVulnerabilityName` | |

`record.description()` returns the English description. `record.cwe_ids` is
the weakness values (`CWE-787`, `NVD-CWE-noinfo`, and so on).

Each CVSS object has `source`, `type` (`Primary` or `Secondary`), and
`cvss_data` (`vector_string`, `base_score`, and the version's metrics).
v2 also carries NVD's `base_severity`, exploitability and impact scores, and
the privilege flags. v3.0 and v3.1 carry exploitability and impact scores on
the wrapper. v4.0 carries threat and environmental scores on `cvss_data`
when NVD sends them.

## Breaking changes from 0.1.x

```python
# 0.1.x
raw = api.get_cve_by_id("CVE-2024-30078")
if raw is None:
    ...
cve_id = raw["vulnerabilities"][0]["cve"]["id"]

# 0.2.0
from nvd_client import NvdNotFoundError

try:
    record = api.get_cve_by_id("CVE-2024-30078")
except NvdNotFoundError:
    ...
cve_id = record.id
document = record.model_dump(by_alias=True, mode="json")
```

Date arguments are `datetime` objects. Strings are rejected. See
[CHANGELOG.md](CHANGELOG.md) for the full list, including the Python version
and the removal of `pytz`.

## Configuration

`NvdApi(api_key)` and `NvdApi(api_key, proxy)` still work. Use `NvdConfig`
when you need the rest.

| Setting | Default | Role |
| --- | --- | --- |
| `base_url` | `https://services.nvd.nist.gov/rest/json` | CVE and CPE Match paths are appended |
| `api_key` | `None` | sent as the `apiKey` header; empty becomes `None` |
| `timeout` | `30` seconds | a float, or `(connect, read)` |
| `results_per_page` | `2000` | CVE page size when a call omits `per_page` |
| `cpe_results_per_page` | `500` | CPE Match page size |
| `rate_limit_delay` | `None` | seconds between requests; `None` picks the NVD window |
| `max_retries` | `4` | extra attempts after the first request |
| `backoff_factor` | `1.0` | wait `factor * 2**attempt` seconds, capped by `max_backoff` |
| `max_backoff` | `60` | cap for the computed backoff, not for `Retry-After` |
| `user_agent` | `nvd-client/<version>` | `User-Agent` header |
| `proxy` | `None` | used for `http` and `https` unless a call passes its own |

When `proxy` is unset, `requests` still honors `HTTP_PROXY` and `HTTPS_PROXY`.

The config object is frozen. Build a new client to change it. A non-empty
`api_key` or `proxy` argument overrides the config. The API key is not
included in `repr(client)`.

Pass an API key from the environment. Do not hard-code it.

```python
import os
from nvd_client import NvdApi, NvdConfig

config = NvdConfig(
    api_key=os.environ.get("NVD_API_KEY"),
    timeout=(5.0, 60.0),
    results_per_page=100,
    user_agent="research-scanner/1.0",
)
```

Request a key at <https://nvd.nist.gov/developers/request-an-api-key>. Without
one, NVD allows 5 requests in a rolling 30 seconds. With one, it allows 50.
The client waits 6 seconds between calls when there is no key and 0.6 seconds
when there is. NIST also suggests sleeping for several seconds so bursts are
not rejected; set `rate_limit_delay=6` to do that even with a key. `0`
disables the pause.

Retries cover connection errors and HTTP 403, 429, 500, 502, 503, and 504.
NVD uses 403 for rate limits as well as for a bad key. A 403 whose message
says the API key is invalid is not retried. A `Retry-After` header replaces
the exponential wait.

## Usage

```python
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(api_key=os.environ.get("NVD_API_KEY"), results_per_page=100)
with NvdApi(config=config) as api:
    page = api.get_all_cves()
    print(page.total_results)
    if page.cves:
        first = page.cves[0]
        print(first.id, first.description())
        print(first.model_dump_json(by_alias=True, indent=2))

    record = api.get_cve_by_id("CVE-2024-30078")
    print(record.id, record.vuln_status, record.cwe_ids)
    for score in record.metrics.cvss_metric_v31:
        print(score.type, score.cvss_data.base_score, score.cvss_data.vector_string)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=2)
    recent = api.get_cve_by_date(
        per_page=50,
        publish_start_date=start,
        publish_end_date=end,
    )
    print(f"{len(recent.cves)} of {recent.total_results} published in the last two days")

    # Aware values from zoneinfo are converted to UTC before the request.
    # Windows needs the tzdata package for ZoneInfo names.
    local_start = datetime(2024, 6, 1, tzinfo=ZoneInfo("America/New_York"))
    local_end = datetime(2024, 6, 3, tzinfo=ZoneInfo("America/New_York"))
    windows = api.get_cve_by_cpe(
        cpe_name="cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
        per_page=20,
        publish_start_date=local_start,
        publish_end_date=local_end,
    )
    for cve in windows.cves:
        print(cve.id)
```

`datetime.now()` without a timezone is treated as UTC, not as the machine's
local zone. Prefer `datetime.now(timezone.utc)`. Both ends of a range are
required, and the span cannot be longer than 120 days. The client sends
`YYYY-MM-DDTHH:MM:SS.sss+00:00` and lets `requests` encode the `+` as `%2B`.

To read the next page, add this page's size to `start_index`. There is no
automatic pager. Keep the client open for the whole loop:

```python
end = datetime.now(timezone.utc)
start = end - timedelta(days=7)
with NvdApi() as api:
    offset = 0
    while True:
        page = api.get_cve_by_date(
            per_page=200,
            offset=offset,
            publish_start_date=start,
            publish_end_date=end,
        )
        for cve in page.cves:
            print(cve.id)
        if not page.cves:
            break
        offset = page.start_index + page.results_per_page
        if offset >= page.total_results:
            break
```

CPE calls use the same `per_page` and `offset` arguments against `/cpematch/2.0`.

```python
with NvdApi() as api:
    matches = api.get_cpes_by_cve("CVE-2024-30078")
    for item in matches.matches:
        print(item.criteria, item.status, len(item.matches))
```

A call can take its own proxy. That proxy replaces the one on the client for
that request only:

```python
with NvdApi(proxy="http://127.0.0.1:8080") as api:
    api.get_all_cves(per_page=10, proxy="socks5h://127.0.0.1:1080")
```

## Dates and the empty result

A page with `total_results == 0` means NVD accepted the query and found no
CVEs. A transport problem, an HTTP 403/429/503, or a bad document raises, so
a failure is not printed as an empty value.

The 0.1.x sample passed `datetime.now()` from a local clock and built the
query string itself. NVD reads an offset-less timestamp as GMT, and a raw
`+` in an offset is decoded as a space unless it is `%2B`. Either mistake
returns no rows or an error that the old client turned into `None`.

## Development

```sh
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict nvd_client
pytest
```

Tests mock HTTP. They do not call NVD. GitHub Actions runs those commands on
Python 3.10 through 3.14.

## Author

Ahur4, [Telegram](https://t.me/Ahura_rahmani).

## License

MIT. See [LICENSE](LICENSE).
