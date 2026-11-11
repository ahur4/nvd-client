# Configuration

`NvdConfig` is a frozen dataclass. Build a new config and a new client to change it. Invalid config values raise `ValueError` when the config is constructed. They are not `NvdClientError` subclasses. Query mistakes raised later by a method are `InvalidParametersError`, documented in [Error handling](errors.md).

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

`NvdApi(api_key)` and `NvdApi(api_key, proxy)` still work. A non-`None` `api_key` or `proxy` argument overrides the same field on `config`, and the client builds a new `NvdConfig` so validation runs again. When both arguments are `None`, the object you passed is used as-is.

```python
from nvd_client import NvdApi, NvdConfig

api = NvdApi("top-secret", "http://proxy.example:8080", config=NvdConfig(timeout=12))
```

`repr(api)` and `str(api)` report whether a key is set. They do not include the key.

```text
NvdApi(base_url='https://services.nvd.nist.gov/rest/json', api_key=set)
```

One client may be shared across threads. Calls take turns on the rate-limit clock. See [Retries and rate limiting](retries.md).

## Fields

| Field | Default | What it does |
| --- | --- | --- |
| `base_url` | `https://services.nvd.nist.gov/rest/json` | CVE calls use `{base_url}/cves/2.0`. CPE match calls use `{base_url}/cpematch/2.0`. Must be `http` or `https`. A trailing slash is removed. |
| `api_key` | `None` | Sent as the `apiKey` header when it is set. Raises the NVD rate limit from 5 to 50 requests per 30 seconds. |
| `timeout` | `30.0` | Seconds, or a `(connect, read)` pair. Passed through to `requests`. Each part must be greater than 0. |
| `results_per_page` | `2000` | CVE page size when a call omits `per_page`. NVD's maximum is 2000 (`MAX_CVE_RESULTS_PER_PAGE`). |
| `cpe_results_per_page` | `500` | CPE Match page size when a call omits `per_page`. NVD's maximum is 500 (`MAX_CPE_RESULTS_PER_PAGE`). |
| `rate_limit_delay` | `None` | Seconds to wait between HTTP calls. `None` selects 6.0 without a key and 0.6 with one. `0` disables the wait. |
| `max_retries` | `4` | Extra attempts after the first request. `0` means one attempt and no retry. |
| `backoff_factor` | `1.0` | Wait `backoff_factor * 2**attempt` seconds between retries, unless `Retry-After` is set. |
| `max_backoff` | `60.0` | Cap on that computed wait. A `Retry-After` value is not capped. |
| `user_agent` | `""`, replaced when blank | `User-Agent` header. A blank value becomes `nvd-client/<version> (+https://github.com/ahur4/nvd-client)`. |
| `proxy` | `None` | Used for both `http` and `https`. A `proxy=` argument on a single call replaces it for that call. |

`effective_rate_limit_delay` is the delay the client actually sleeps. An explicit `rate_limit_delay` wins, including `0`. Otherwise the delay is the published window divided by the number of allowed requests.

The module also exposes the numbers that delay is built from: `RATE_LIMIT_WINDOW_SECONDS` (30), `RATE_LIMIT_REQUESTS_WITHOUT_KEY` (5), and `RATE_LIMIT_REQUESTS_WITH_KEY` (50). `DEFAULT_BASE_URL` and `DEFAULT_USER_AGENT` are the values used above.

## API key header

A key is sent on every request as the HTTP header `apiKey`. It is not a query parameter. An empty or whitespace `api_key` is stored as `None`, and the header is omitted. A non-string `api_key` is also stored as `None`.

NVD's published windows, from the [API start page](https://nvd.nist.gov/developers/start-here):

| Credential | Limit | Default delay |
| --- | --- | --- |
| No API key | 5 requests in a rolling 30 seconds | 6.0 seconds |
| API key | 50 requests in a rolling 30 seconds | 0.6 seconds |

The default delay is the window divided by the number of allowed requests, so a single client stays inside the limit. The first call does not wait. NIST also recommends sleeping for several seconds between requests so bursts are not rejected. Set `rate_limit_delay=6` to do that even when a key is configured.

Request a key from NIST: [Request an API key](https://nvd.nist.gov/developers/request-an-api-key).

## Timeouts

`timeout` is passed to `requests` unchanged.

- A single number is the whole-request timeout in seconds.
- A pair `(connect, read)` sets the connect timeout and the read timeout separately.
- The tuple must have length 2.
- Each part must be a number greater than 0. `0`, a negative number, and `bool` raise `ValueError`.

A timeout that survives the retries raises `NvdApiError`. `status_code` is `None` in that case, because no response arrived. See [Retries and rate limiting](retries.md).

## Proxy

`proxy` is one URL, applied to both `http` and `https`. A per-call `proxy=` argument replaces the client proxy for that request only. In 0.1.x the client proxy won and the argument was ignored.

```python
from nvd_client import NvdApi, NvdConfig

config = NvdConfig(proxy="http://proxy.example:8080")

with NvdApi(config=config) as api:
    api.get_cve_by_id("CVE-2024-30078", proxy="http://other.example:8080")
```

When `proxy` is left unset, `requests` still honors `HTTP_PROXY` and `HTTPS_PROXY`. A `socks5://` or `socks5h://` URL needs the `socks` extra (`PySocks`). The client does not import that package itself.

A non-string `proxy` on `NvdConfig` raises `ValueError`. A blank string is stored as `None`. A blank `proxy` passed to a single call raises `InvalidParametersError` instead, and no request is sent.

## Values that raise `ValueError`

These are rejected in `NvdConfig.__post_init__`:

| Value | Why |
| --- | --- |
| `base_url` that does not start with `http://` or `https://` | Only HTTP(S) endpoints are accepted. |
| `timeout` of `0`, a negative number, a `bool`, or a pair that is not two positive numbers | `requests` would not treat that as a usable timeout. |
| `results_per_page` outside `1..2000`, or not an `int` | NVD's CVE maximum is 2000. |
| `cpe_results_per_page` outside `1..500`, or not an `int` | NVD's CPE Match maximum is 500. |
| `rate_limit_delay` set to a negative number or a non-number | `None` is the automatic delay. `0` is allowed and disables the wait. |
| `max_retries` below `0`, or not an `int` | `0` means "do not retry". |
| `backoff_factor` or `max_backoff` below `0`, or not a number | `0` is allowed. |
| `proxy` that is not a string and not `None` | The value has to be a URL. |

`bool` is rejected wherever an `int` is required, because `bool` is a subclass of `int`.

A page size or offset that is illegal for one call, rather than for the config, raises `InvalidParametersError` from the method. `per_page=None` on a method uses the config default and does not raise.
