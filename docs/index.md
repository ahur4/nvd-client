# nvd-client

Typed Python client for the [National Vulnerability Database](https://nvd.nist.gov/) CVE and CPE Match APIs (version 2.0).

The National Vulnerability Database is NIST's repository of publicly disclosed vulnerabilities. Each record is a CVE, with descriptions, references, CVSS scores, weaknesses, and the CPE configurations that say which products are affected. `nvd-client` calls the NVD REST API and returns those documents as pydantic models.

Use it when a vulnerability scanner, asset inventory, or research notebook needs CVE or CPE match data and should not parse raw JSON by hand. It is a read-only client. It does not submit data to NVD, and it does not walk result pages for you.

This site describes **0.2.1**. That release adds this documentation. Client behavior is the 0.2.0 behavior.

## Install

Python 3.10 or newer.

```console
pip install nvd-client
```

HTTP and HTTPS proxies work with the base install. A `socks5://` or `socks5h://` proxy needs the extra:

```console
pip install "nvd-client[socks]"
```

Pass an API key when you have one. The same calls work without a key, on NVD's public rate. Request a key from NIST: [Request an API key](https://nvd.nist.gov/developers/request-an-api-key).

## What a call returns

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

The CVE base path is `{base_url}/cves/2.0`. The CPE Match base path is `{base_url}/cpematch/2.0`. The default `base_url` is `https://services.nvd.nist.gov/rest/json`.

```python
from nvd_client import NvdApi, NvdConfig
```

`nvd_client.__version__` is the installed version. It matches `[project].version` in `pyproject.toml`.

## Where to go next

- [Quickstart](quickstart.md) walks through a CVE lookup, a date range, a CPE match, and paging.
- [Configuration](configuration.md) lists every `NvdConfig` field.
- [Data models](models.md) covers the response models and serialization.
- [Error handling](errors.md) is the exception hierarchy.
- [Retries and rate limiting](retries.md) is the wait between calls and the backoff after a failure.
- [API reference](reference/index.md) is generated from the source.
- [Migrating from 0.1.x](migrating.md) lists the 0.2.0 breaks.
- [Changelog](changelog.md) is the repository changelog.

## Building this site

From a checkout:

```console
pip install -e ".[docs]"
mkdocs serve
```

`mkdocs build --strict` fails on warnings, including a broken nav link or a docstring cross-reference the API pages cannot resolve. GitHub Actions runs that command on every pull request. A push to `main` uploads the built `site/` directory and deploys it to GitHub Pages. The repository's Pages source has to be GitHub Actions before that deploy can succeed.

The published URL is <https://ahur4.github.io/nvd-client/>.

Lint and tests, which mock HTTP and do not call NVD:

```console
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict nvd_client
pytest
```
