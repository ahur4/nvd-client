# nvd-client

Typed Python client for the National Vulnerability Database CVE and CPE Match APIs (version 2.0).

[![PyPI](https://img.shields.io/pypi/v/nvd-client)](https://pypi.org/project/nvd-client/)
[![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/github/license/ahur4/nvd-client)](https://github.com/ahur4/nvd-client/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/ahur4/nvd-client/ci.yml?branch=main&label=CI)](https://github.com/ahur4/nvd-client/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/docs-mkdocs-0A7AAA)](https://ahur4.github.io/nvd-client/)

**Documentation:** <https://ahur4.github.io/nvd-client/>

The [National Vulnerability Database](https://nvd.nist.gov/) is NIST's repository of publicly disclosed vulnerabilities. Each record is a CVE, with descriptions, references, CVSS scores, weaknesses, and the CPE configurations that say which products are affected. `nvd-client` calls the NVD REST API 2.0 and returns those documents as pydantic models.

Use it when a vulnerability scanner, asset inventory, or research notebook needs CVE or CPE match data and should not parse raw JSON by hand. It is a read-only client. It does not submit data to NVD.

## Contents

- [Documentation](https://ahur4.github.io/nvd-client/)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Rate limits and retries](#rate-limits-and-retries)
- [Return values](#return-values)
- [Errors](#errors)
- [Migrating from 0.1.x](#migrating-from-01x)
- [Development](#development)
- [Further reading](#further-reading)

## Installation

Python 3.10 or newer.

```console
pip install nvd-client
```

HTTP and HTTPS proxies work with the base install. SOCKS proxies need the extra:

```console
pip install "nvd-client[socks]"
```

From a checkout, including the linters and test runner:

```console
pip install -e ".[dev]"
```

## Quickstart

Pass an API key from the environment when you have one. The same calls work without a key; they then use NVD's public rate (see [Rate limits and retries](#rate-limits-and-retries)).

This program looks up one CVE, one page of CVEs published in the last seven days, and the CPE match strings for that CVE. Seven days is inside NVD's 120-day maximum. The datetimes are timezone-aware UTC.

```python
import os
from datetime import datetime, timedelta, timezone

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(
    api_key=os.environ.get("NVD_API_KEY"),
    results_per_page=100,
)
end = datetime.now(timezone.utc)
start = end - timedelta(days=7)

with NvdApi(config=config) as api:
    record = api.get_cve_by_id("CVE-2024-30078")
    print(record.id, record.vuln_status)
    print(record.description())
    print(record.cwe_ids)
    for metric in record.metrics.cvss_metric_v31:
        data = metric.cvss_data
        print(metric.type, data.base_score, data.vector_string)

    page = api.get_cve_by_date(
        publish_start_date=start,
        publish_end_date=end,
        per_page=50,
    )
    print(f"{len(page.cves)} of {page.total_results}")
    for cve in page.cves:
        print(cve.id, cve.published)

    found = api.get_cpes_by_cve("CVE-2024-30078", per_page=20)
    for item in found.matches:
        print(item.criteria, item.status, len(item.matches))
```

`get_cve_by_id` returns a `CveRecord`. A missing id raises `NvdNotFoundError`. `get_cve_by_date` returns one page, a `CveListResponse`: `total_results` is the size of the whole match, and `cves` is only this page. `get_cpes_by_cve` calls the CPE Match API (`/cpematch/2.0`) and returns a `CpeMatchResponse`. A page with `total_results == 0` matched nothing. It is not an error.

`get_cve_by_cpe` goes the other way: CVEs whose applicability statement matches a CPE name. NVD requires a real part, vendor, product, and version in that name (`*` is not enough for those components). The same publish and modify date arguments are accepted.

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

`modify_start_date` and `modify_end_date` filter on `lastModified`. A publish range and a modify range may be sent in one call. Each pair still has to be complete and no longer than 120 days.

To read past the first page, advance `offset` by the page size. There is no automatic pager.

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

### Dates

The client sends `YYYY-MM-DDTHH:MM:SS.sss+00:00`. `requests` percent-encodes the `+` as `%2B`, which is what NVD requires.

- An aware datetime, including one built with `zoneinfo.ZoneInfo`, is converted to UTC.
- A naive datetime is treated as UTC, not as the machine's local zone. `datetime.now()` is naive. Use `datetime.now(timezone.utc)`.
- Named zones on Windows need the `tzdata` package. `timezone.utc` does not.
- One end without the other, an end before the start, or a span longer than 120 days raises `InvalidParametersError` before any request is sent.
- A non-`datetime` value raises `InvalidDateFormatError`.

Timestamps in NVD responses are parsed as `datetime`. Values without an offset stay naive. Values with `Z` or a numeric offset are aware.

## Configuration

`NvdConfig` is frozen. Build a new config and a new client to change it. `NvdApi(api_key)` and `NvdApi(api_key, proxy)` still work. A non-`None` `api_key` or `proxy` argument overrides the same field on `config`. An empty or whitespace `api_key` is stored as `None`.

`repr(client)` reports whether a key is set. It does not include the key.

| Field | Default | What it does |
| --- | --- | --- |
| `base_url` | `https://services.nvd.nist.gov/rest/json` | CVE calls use `{base_url}/cves/2.0`. CPE match calls use `{base_url}/cpematch/2.0`. Must be `http` or `https`. |
| `api_key` | `None` | Sent as the `apiKey` header. Raises the NVD rate limit from 5 to 50 requests per 30 seconds. |
| `timeout` | `30` | Seconds, or a `(connect, read)` pair. Passed through to `requests`. Each part must be greater than 0. |
| `results_per_page` | `2000` | CVE page size when a call omits `per_page`. NVD's maximum is 2000. |
| `cpe_results_per_page` | `500` | CPE Match page size when a call omits `per_page`. NVD's maximum is 500. |
| `rate_limit_delay` | `None` | Seconds to wait between HTTP calls. `None` selects 6.0 without a key and 0.6 with one. `0` disables the wait. |
| `max_retries` | `4` | Extra attempts after the first request. |
| `backoff_factor` | `1.0` | Wait `backoff_factor * 2**attempt` seconds between retries, unless `Retry-After` is set. |
| `max_backoff` | `60` | Cap on that computed wait. A `Retry-After` value is not capped. |
| `user_agent` | `nvd-client/<version> (+https://github.com/ahur4/nvd-client)` | `User-Agent` header. |
| `proxy` | `None` | Used for both `http` and `https`. A `proxy=` argument on a single call replaces it for that call. |

`per_page=None` on a method uses the config default. `per_page` outside `1..2000` (CVE) or `1..500` (CPE match), or a negative `offset`, raises `InvalidParametersError`.

Invalid config values raise `ValueError` when the config is constructed: a non-HTTP base URL, a non-positive timeout, a page size outside NVD's maximum, or a negative retry or backoff setting.

When `proxy` is left unset, `requests` still honors `HTTP_PROXY` and `HTTPS_PROXY`. A `socks5://` or `socks5h://` URL needs the `socks` extra.

```python
import os

from nvd_client import NvdApi, NvdConfig

config = NvdConfig(
    api_key=os.environ.get("NVD_API_KEY"),
    timeout=(5.0, 60.0),
    results_per_page=100,
    user_agent="research-scanner/1.0",
)

with NvdApi(config=config) as api:
    page = api.get_all_cves()
```

Request a key from NIST: [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

Use the client as a context manager, or call `close()`, so the connection pool is released. One client may be shared across threads. Calls take turns on the rate-limit clock.

## Rate limits and retries

NVD's published windows, from the [API start page](https://nvd.nist.gov/developers/start-here):

| Credential | Limit | Default delay |
| --- | --- | --- |
| No API key | 5 requests in a rolling 30 seconds | 6.0 seconds |
| API key | 50 requests in a rolling 30 seconds | 0.6 seconds |

The default delay is the window divided by the number of allowed requests, so a single client stays inside the limit. The first call does not wait. NIST also recommends sleeping for several seconds between requests so bursts are not rejected. Set `rate_limit_delay=6` to do that even when a key is configured.

The client retries connection errors and HTTP **403, 429, 500, 502, 503, and 504**. NVD uses 403 both for rate limits and for a rejected key. A 403 whose message says the API key is invalid is not retried. Any other 4xx, including 400 and 404, fails immediately.

With the defaults, a failure is followed by waits of 1, 2, 4, and 8 seconds (`backoff_factor * 2**attempt`), then the error is raised. `max_backoff` caps that series. If the response has `Retry-After` (a number of seconds or an HTTP date), that value replaces the computed wait.

After the retries are used up, a 403 or 429 raises `NvdRateLimitError`. Other exhausted failures raise `NvdApiError`.

## Return values

Every successful call returns a pydantic model. Nothing returns a `dict` or `None`.

| Method | Endpoint | Returns |
| --- | --- | --- |
| `get_all_cves(per_page=None, offset=0, proxy=None)` | `/cves/2.0` | `CveListResponse` |
| `get_cve_by_id(cve_id, proxy=None)` | `/cves/2.0` | `CveRecord` |
| `get_cve_by_date(...)` | `/cves/2.0` | `CveListResponse` |
| `get_cve_by_cpe(cpe_name, ...)` | `/cves/2.0` | `CveListResponse` |
| `get_cpes_by_cve(cve_id, ...)` | `/cpematch/2.0` | `CpeMatchResponse` |
| `get_cpes_by_criteria(criteria, ...)` | `/cpematch/2.0` | `CpeMatchResponse` |
| `get_cpes_by_criteria_name_id(criteria_name_id, ...)` | `/cpematch/2.0` | `CpeMatchResponse` |

`get_cve_by_date` and `get_cve_by_cpe` also take `per_page`, `offset`, `publish_start_date`, `publish_end_date`, `modify_start_date`, `modify_end_date`, and `proxy`. The CPE match methods take `per_page`, `offset`, and `proxy`.

### Serialization

Attributes are snake_case. The NVD names are aliases, so both forms validate.

```python
record.model_dump()
record.model_dump(by_alias=True)
record.model_dump(by_alias=True, mode="json", exclude_none=True)
record.model_dump_json(by_alias=True, indent=2)
```

`model_dump()` uses Python names (`last_modified`) and leaves `datetime` objects in place. `by_alias=True` uses the NVD names (`lastModified`). `mode="json"` and `model_dump_json()` render datetimes as ISO strings.

Unknown JSON keys are kept (`extra="allow"`) and show up in `model_dump()`. A field NVD adds later does not drop the rest of the document and is not discarded. Metric groups that NVD omits are empty lists, not `None`.

### `CveListResponse`

| Attribute | NVD name | Meaning |
| --- | --- | --- |
| `results_per_page` | `resultsPerPage` | Records in this response |
| `start_index` | `startIndex` | Offset NVD used |
| `total_results` | `totalResults` | Size of the full match |
| `format` | `format` | Response format name |
| `version` | `version` | API version string |
| `timestamp` | `timestamp` | When NVD generated the page |
| `vulnerabilities` | `vulnerabilities` | `CveItem` wrappers |
| `cves` | | `CveRecord` objects on this page |

### `CveRecord`

`description(lang="en")` returns that language's text, or `None`. `cwe_ids` is the weakness description values (`CWE-787`, `NVD-CWE-noinfo`, and similar).

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
| `weaknesses` | `weaknesses` | `Weakness`: `source`, `type`, `description` |
| `configurations` | `configurations` | CPE applicability tree |
| `affected` | `affected` | `Affected`: `source`, `affected_data` |
| `cve_tags` | `cveTags` | `CveTag`: `source_identifier`, `tags` |
| `vendor_comments` | `vendorComments` | `organization`, `comment`, `last_modified` |
| `evaluator_comment` | `evaluatorComment` | |
| `evaluator_solution` | `evaluatorSolution` | |
| `evaluator_impact` | `evaluatorImpact` | |
| `cisa_exploit_add` | `cisaExploitAdd` | `date`, when the CVE is in the KEV catalog |
| `cisa_action_due` | `cisaActionDue` | `date` |
| `cisa_required_action` | `cisaRequiredAction` | |
| `cisa_vulnerability_name` | `cisaVulnerabilityName` | |

`Metrics` holds `cvss_metric_v2`, `cvss_metric_v30`, `cvss_metric_v31`, `cvss_metric_v40`, and `ssvc_v203`. Each CVSS metric has `source`, `type` (`Primary` or `Secondary`), and `cvss_data` (`version`, `vector_string`, `base_score`, plus that version's base metrics). v2, v3.0, and v3.1 wrappers also carry `exploitability_score` and `impact_score` when NVD sends them. v2 adds `base_severity` and the privilege flags. v4 scores that NVD attaches to the vector (threat, environmental) live on `cvss_data`.

A configuration node (`ConfigNode`) has `operator`, `negate`, and `cpe_match`. Each `CpeMatch` has `vulnerable`, `criteria`, `match_criteria_id`, and the optional version bounds. `AffectedProduct` carries `vendor`, `product`, `versions`, and the other product fields from the NVD affected schema.

The full field list is `nvd_client.models`.

### `CpeMatchResponse`

| Attribute | NVD name | Meaning |
| --- | --- | --- |
| `results_per_page` | `resultsPerPage` | Match strings in this response |
| `start_index` | `startIndex` | Offset NVD used |
| `total_results` | `totalResults` | Size of the full match |
| `format` | `format` | |
| `version` | `version` | |
| `timestamp` | `timestamp` | |
| `match_strings` | `matchStrings` | Wrappers around `CpeMatchString` |
| `matches` | | The `CpeMatchString` objects on this page |

`CpeMatchString` has `criteria`, `match_criteria_id`, `created`, `last_modified`, `status`, optional version bounds, `cpe_last_modified`, and `matches` (`CpeNameMatch`: `cpe_name`, `cpe_name_id`).

## Errors

```text
NvdClientError
├── InvalidDateFormatError
├── InvalidParametersError
├── InvalidCVEIDError
├── NvdApiError
│   ├── NvdRateLimitError
│   └── NvdNotFoundError
└── NvdResponseError
```

| Exception | When it is raised |
| --- | --- |
| `InvalidCVEIDError` | The id is not `CVE-YYYY-NNNN` with at least four digits in the sequence. No request is sent. |
| `InvalidDateFormatError` | A date argument is not a `datetime`. |
| `InvalidParametersError` | A date range is incomplete, reversed, or longer than 120 days. `per_page` or `offset` is out of range. A required CPE name, criteria, or match-criteria id is blank. |
| `ValueError` | `NvdConfig` itself is invalid (base URL, timeout, page-size bounds, negative retry settings). |
| `NvdNotFoundError` | HTTP 404, or `get_cve_by_id` received an empty page. An empty id lookup is still HTTP 200, so `status_code` is 200. Subclass of `NvdApiError`. |
| `NvdRateLimitError` | HTTP 403 or 429 after retries. Subclass of `NvdApiError`. |
| `NvdApiError` | Any other HTTP error, including a rejected API key, and connection or timeout failures after retries. |
| `NvdResponseError` | The body was not JSON, or it did not match the pydantic model. |

`NvdApiError` (and its subclasses) expose `status_code` and `url`. `status_code` is `None` when the failure happened before a response, for example a timeout.

```python
from nvd_client import NvdApi, NvdNotFoundError, NvdRateLimitError

with NvdApi() as api:
    try:
        record = api.get_cve_by_id("CVE-2024-30078")
    except NvdNotFoundError as exc:
        print(exc.status_code, exc)
    except NvdRateLimitError:
        raise
```

## Migrating from 0.1.x

0.2.0 changes the return types and stops hiding failed requests. The method names are the same.

```python
# 0.1.x returned a dict, or None when the request failed.
raw = api.get_cve_by_id("CVE-2024-30078")
if raw is None:
    ...
else:
    cve_id = raw["vulnerabilities"][0]["cve"]["id"]

# 0.2.0 returns a CveRecord and raises when the CVE is missing.
from nvd_client import NvdNotFoundError

try:
    record = api.get_cve_by_id("CVE-2024-30078")
except NvdNotFoundError:
    ...
else:
    cve_id = record.id
    document = record.model_dump(by_alias=True, mode="json")
```

Collection calls (`get_all_cves`, `get_cve_by_date`, `get_cve_by_cpe`) return `CveListResponse`. Read `page.cves`, not `page["vulnerabilities"]`. CPE match calls return `CpeMatchResponse`.

Other breaks:

- Python 3.10 or newer is required.
- Failures raise the exceptions in [Errors](#errors). Check `total_results` for an empty match. Do not check for `None`.
- Date arguments must be `datetime` values. Strings are rejected. Naive values are UTC. Ranges longer than 120 days are rejected locally.
- `pytz` is not a dependency. The old import existed so the package could build an unused `Asia/Tehran` zone, and a fresh `pip install` failed because `pytz` was never declared in `install_requires`.
- `per_page` above NVD's maximum raises `InvalidParametersError`.
- A `proxy` passed to one call overrides the client proxy. In 0.1.x the client proxy won and the argument was ignored.
- `str(client)` describes the base URL and whether a key is set.
- `model_dump()` is the replacement for treating the response as a dictionary. Pass `by_alias=True` when you need NVD's camelCase keys.

See [CHANGELOG.md](CHANGELOG.md) for the dependency changes that went with this release.

## Development

```console
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict nvd_client
pytest
```

Documentation site:

```console
pip install -e ".[docs]"
mkdocs build --strict
mkdocs serve
```

Tests mock HTTP. They do not call NVD. GitHub Actions runs the same checks on Python 3.10 through 3.14, and runs `mkdocs build --strict` on pull requests. Pushes to `main` publish the site to GitHub Pages.

## Further reading

- [Documentation](https://ahur4.github.io/nvd-client/)
- [NVD API quick start](https://nvd.nist.gov/developers/start-here), including the rate limits
- [CVE API](https://nvd.nist.gov/developers/vulnerabilities)
- [CPE and CPE Match APIs](https://nvd.nist.gov/developers/products)
- [Request an API key](https://nvd.nist.gov/developers/request-an-api-key)
- [Changelog](CHANGELOG.md)
- [MIT license](LICENSE)

Maintained by [Ahur4](https://github.com/ahur4).
