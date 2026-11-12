# Migrating from 0.1.x

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

Collection calls (`get_all_cves`, `get_cve_by_date`, `get_cve_by_cpe`) return `CveListResponse`. Read `page.cves`, not `page["vulnerabilities"]`. CPE match calls return `CpeMatchResponse`. Read `page.matches`.

## Other breaks

- Python 3.10 or newer is required.
- Failures raise the exceptions in [Error handling](errors.md). Check `total_results` for an empty match. Do not check for `None`.
- Date arguments must be `datetime` values. Strings are rejected. Naive values are UTC. Ranges longer than 120 days are rejected locally. The wire format is `YYYY-MM-DDTHH:MM:SS.sss+00:00`.
- `pytz` is not a dependency. The old import existed so the package could build an unused `Asia/Tehran` zone, and a fresh `pip install` failed because `pytz` was never declared in `install_requires`. Pass timezone-aware datetimes from the standard library (`datetime.timezone` or `zoneinfo`).
- `per_page` above NVD's maximum raises `InvalidParametersError`. The maximum is 2000 for CVEs and 500 for CPE match strings.
- A `proxy` passed to one call overrides the client proxy. In 0.1.x the client proxy won and the argument was ignored.
- `str(client)` describes the base URL and whether a key is set. The key itself is not included.
- `model_dump()` is the replacement for treating the response as a dictionary. Pass `by_alias=True` when you need NVD's camelCase keys. See [Data models](models.md).

## Dependencies

Direct dependencies are lower bounds only. `urllib3` and `idna` are declared directly because `requests` still allows versions with known vulnerabilities. `PySocks` is an optional `socks` extra. `pydantic` 2.x is required.

| Package | 0.1.x | 0.2.x |
| --- | --- | --- |
| requests | `==2.32.3` (with the `socks` extra) | `>=2.33.0` |
| urllib3 | `==2.2.1` | `>=2.8.0,<3` |
| idna | `==3.7` | `>=3.7,<4` |
| certifi | `==2024.6.2` | not declared (pulled in by requests) |
| charset-normalizer | `==3.3.2` | not declared (pulled in by requests) |
| pytz | imported, listed only in `requirements.txt` | removed |
| pydantic | not used | `>=2.4,<3` |
| PySocks | always, via `requests[socks]` | optional extra `socks` |

The [changelog](changelog.md) is the release history.
