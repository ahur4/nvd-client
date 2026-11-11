# Retries and rate limiting

Two clocks are independent.

- The rate-limit delay spaces the start of successful and retried requests so one client stays inside NVD's published window.
- The retry backoff waits after a failed attempt, then the rate-limit delay runs again before the next send.

`max_retries` is the number of extra attempts after the first request. The default is 4, so a call may be sent 5 times. `max_retries=0` sends once.

## Rate limit

NVD's published windows, from the [API start page](https://nvd.nist.gov/developers/start-here):

| Credential | Limit | Default `effective_rate_limit_delay` |
| --- | --- | --- |
| No API key | 5 requests in a rolling 30 seconds | 6.0 seconds |
| API key (`apiKey` header) | 50 requests in a rolling 30 seconds | 0.6 seconds |

The default is `RATE_LIMIT_WINDOW_SECONDS / allowed_requests` (`30 / 5` or `30 / 50`). Set `rate_limit_delay` to override it. `0` disables the wait. A negative value raises `ValueError` when the config is built.

The first request from a client does not wait. Each later request waits, when needed, so that consecutive requests start at least `effective_rate_limit_delay` seconds apart. Time spent inside the HTTP call counts. If a response takes longer than the delay, the next request starts immediately.

The wait runs under a lock, and the HTTP call runs outside it. Shared use from several threads is safe: the clock spaces when each request may start, and in-flight responses can overlap. `repr` still does not include the API key.

NIST also recommends sleeping for several seconds between requests so bursts are not rejected. `rate_limit_delay=6` does that even when a key is configured. The delay is a client-side pause. It is not something NVD returns.

## What is retried

The client retries connection errors (`requests.RequestException`, including timeouts) and HTTP **403, 429, 500, 502, 503, and 504**.

NVD uses 403 both for rate limits and for a rejected key. A 403 whose `message` header or body says the API key is invalid is not retried. The check is case-insensitive and looks for `invalid` together with `api key` or `apikey`, in the header plus the first 500 characters of the body.

Any other 4xx, including 400 and 404, fails immediately.

## Backoff

With the defaults (`backoff_factor=1.0`, `max_backoff=60`), a failure is followed by waits of 1, 2, 4, and 8 seconds (`backoff_factor * 2**attempt`), then the error is raised. `attempt` starts at 0. `max_backoff` caps that series, so a factor of 1 and a cap of 3 sleeps 1, 2, then 3 seconds.

If the response has `Retry-After`, that value replaces the computed wait. It is not capped by `max_backoff`.

- A numeric `Retry-After` is a number of seconds (`float`).
- An HTTP-date `Retry-After` is the delay until that instant. A date without a timezone is treated as UTC.
- A value that cannot be parsed is ignored, and the exponential wait is used.
- A negative result is clamped to 0.

The order on a failed attempt is: space for the rate limit, send, sleep the backoff, then loop. The next attempt spaces for the rate limit again before it sends.

## Which exception comes out

After the retries are used up:

| Failure | Exception |
| --- | --- |
| 403 or 429 | `NvdRateLimitError` |
| 500, 502, 503, 504 | `NvdApiError` |
| Connection error or timeout | `NvdApiError` with `status_code is None` |
| 403 for an invalid API key | `NvdApiError` on the first response, no retry |

`NvdRateLimitError` is a subclass of `NvdApiError`. Both expose `status_code` and `url`. The full table, including errors that are not retried, is in [Error handling](errors.md).

```python
from nvd_client import NvdApi, NvdApiError, NvdConfig, NvdRateLimitError

config = NvdConfig(
    api_key=None,
    max_retries=4,
    backoff_factor=1.0,
    max_backoff=60,
    rate_limit_delay=6,
)

with NvdApi(config=config) as api:
    try:
        page = api.get_all_cves(per_page=20)
    except NvdRateLimitError as exc:
        print(exc.status_code, exc.url)
    except NvdApiError as exc:
        print(exc.status_code, exc.url)
```
