# Changelog

## 0.2.2

Documentation and metadata cleanup. No changes to client behavior.

- Removed transient release-status notes from the README and the
  documentation site.

## 0.2.1

Documentation release. No changes to client behavior.

- Added a documentation site (MkDocs Material, with an API reference
  generated from the docstrings) at <https://ahur4.github.io/nvd-client/>.
  GitHub Actions builds it with `mkdocs build --strict` and deploys it
  to GitHub Pages from `main`.
- Added a `docs` extra: `pip install -e ".[docs]"`.
- PyPI project URLs now include Documentation
  (<https://ahur4.github.io/nvd-client/>), Homepage, Source, Repository,
  Issues, and Changelog.

## 0.2.0

This release makes the client match the NVD API 2.0, replaces raw dictionaries
with typed models, and stops hiding failed requests. It is not published to
PyPI by this change.

### Breaking changes

- Python 3.10 or newer is required (3.9 reached end of life in October 2025).
- CVE and CPE methods return pydantic models. They no longer return a `dict`
  or `None`.
  - `get_all_cves`, `get_cve_by_date`, and `get_cve_by_cpe` return
    `CveListResponse`. Records for the page are `response.cves`.
  - `get_cve_by_id` returns one `CveRecord`. A missing id raises
    `NvdNotFoundError`.
  - `get_cpes_by_cve`, `get_cpes_by_criteria`, and
    `get_cpes_by_criteria_name_id` return `CpeMatchResponse`.
  - `model_dump()` uses snake_case. `model_dump(by_alias=True)` uses the
    NVD camelCase names. `model_dump_json()` accepts the same arguments.
- HTTP failures, rate limits, and documents that do not match the schema
  raise `NvdApiError`, `NvdRateLimitError`, `NvdNotFoundError`, or
  `NvdResponseError`. They are not returned as `None`.
- Date arguments must be `datetime` values. Naive values are treated as UTC
  and sent as `YYYY-MM-DDTHH:MM:SS.sss+00:00`. Aware values are converted to
  UTC. A range missing one end, reversed, or longer than 120 days raises
  `InvalidParametersError`.
- `per_page` outside NVD's maximum (2000 for CVEs, 500 for CPE match strings)
  raises `InvalidParametersError` instead of being sent.
- A per-call `proxy` overrides the client proxy. Previously the client proxy
  won and the argument was ignored.
- `str(NvdApi(...))` describes the base URL and whether an API key is set.
  The key itself is not included.
- `pytz` is no longer a dependency. Pass timezone-aware datetimes from the
  standard library (`datetime.timezone` or `zoneinfo`) instead.

### Fixes

- Issue #3: importing the package after `pip install` required `pytz`, but
  `setup.py` never declared it (`requirements.txt` did, and nothing used the
  timezone object). The dependency is removed. Dates use the standard library.
- Issue #2: the sample fetched nothing because every request error was
  swallowed, and because query strings were concatenated by hand. A `+` in a
  UTC offset was not encoded as `%2B`, which NVD requires, and a naive local
  `datetime.now()` was sent as wall-clock time that NVD reads as GMT. Requests
  now go through `params`, timestamps are explicit UTC, and failures raise.

### Other behavior

- Retries with exponential backoff for connection errors and HTTP 403, 429,
  500, 502, 503, and 504. `Retry-After` is honored. A 403 that reports an
  invalid API key is not retried.
- The client waits between calls so it stays inside NVD's published windows:
  6 seconds without an API key (5 requests / 30 seconds) and 0.6 seconds with
  one (50 requests / 30 seconds). Set `rate_limit_delay` to override.
- Optional API key is sent in the `apiKey` header.
- `NvdConfig` controls the base URL, API key, timeout, page size, rate-limit
  delay, retries, backoff, user agent, and proxy.

### Dependencies

Direct dependencies are lower bounds only. Transitive pins that forced old,
vulnerable releases of `urllib3` and `requests` are gone. `urllib3` and
`idna` are declared directly because `requests` still allows versions with
known vulnerabilities. `PySocks` is an optional `socks` extra.

| Package | Before | After |
| --- | --- | --- |
| requests | `==2.32.3` (with the `socks` extra) | `>=2.33.0` |
| urllib3 | `==2.2.1` | `>=2.8.0,<3` |
| idna | `==3.7` | `>=3.7,<4` |
| certifi | `==2024.6.2` | not declared (pulled by requests) |
| charset-normalizer | `==3.3.2` | not declared (pulled by requests) |
| pytz | imported, listed only in `requirements.txt` | removed |
| pydantic | not used | `>=2.4,<3` |
| PySocks | always, via `requests[socks]` | optional extra `socks` |

## 0.1.3.1

Last release published from the previous `setup.py` line. CVE calls returned
decoded JSON dictionaries, or `None` when the request failed.
