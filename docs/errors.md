# Error handling

Failures raise. A query that matches nothing is a normal page whose `total_results` is `0`, and `cves` or `matches` is empty. Check that attribute. Do not check for `None`.

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

`ValueError` is the builtin. `NvdConfig` raises it for a bad setting. It is not a subclass of `NvdClientError`.

| Exception | When it is raised |
| --- | --- |
| `InvalidCVEIDError` | The id is not `CVE-YYYY-NNNN` with at least four digits in the sequence (`CVE-YYYY-` plus `\d{4,}`). No request is sent. `cve_id` is the value that failed. |
| `InvalidDateFormatError` | A date argument is not a `datetime`. `date_str` is the value that failed. If only one end of a range is set, `InvalidParametersError` is raised first. |
| `InvalidParametersError` | A date range is incomplete, reversed, or longer than 120 days. `per_page` or `offset` is out of range or not an `int`. A required CPE name, criteria, or match-criteria id is blank. A per-call `proxy` is blank. `missing_params` lists the incomplete date pair when that is the reason. |
| `ValueError` | `NvdConfig` itself is invalid: base URL, timeout, page-size bounds, a negative retry or backoff setting, or a `proxy` that is not a string. See [Configuration](configuration.md). |
| `NvdNotFoundError` | HTTP 404, or `get_cve_by_id` received an empty page. An empty id lookup is still HTTP 200, so `status_code` is 200 and `url` is the CVE endpoint. Subclass of `NvdApiError`. |
| `NvdRateLimitError` | HTTP 403 or 429 after retries are exhausted. Subclass of `NvdApiError`. A 403 whose message says the API key is invalid is `NvdApiError` instead, and it is not retried. |
| `NvdApiError` | Any other HTTP error, including a rejected API key, and connection or timeout failures after retries. |
| `NvdResponseError` | The body was not JSON, or it did not match the pydantic model. The HTTP call itself succeeded. This exception has no `status_code`. |

`NvdApiError` and its subclasses expose `status_code` and `url`. `status_code` is `None` when the failure happened before a response, for example a timeout or a connection error.

`InvalidParametersError`, `InvalidDateFormatError`, and `InvalidCVEIDError` are raised locally. They do not have `status_code`.

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

## Which status becomes which error

| Response | Retried | Exception after the last attempt |
| --- | --- | --- |
| 404 | No | `NvdNotFoundError` (`status_code` 404) |
| 200 with an empty `get_cve_by_id` page | No | `NvdNotFoundError` (`status_code` 200) |
| 403 or 429, other than a rejected key | Yes | `NvdRateLimitError` |
| 403 that reports an invalid API key | No | `NvdApiError` |
| 400 and any other 4xx outside the retry list | No | `NvdApiError` |
| 500, 502, 503, 504 | Yes | `NvdApiError` |
| Connection error or timeout | Yes | `NvdApiError` (`status_code` is `None`) |
| 200 whose body is not JSON | No | `NvdResponseError` |
| 200 whose JSON does not match the model | No | `NvdResponseError` |

The retry list is 403, 429, 500, 502, 503, and 504, plus `requests` connection failures. The message check for a rejected key looks at the `message` response header and the first 500 characters of the body. It treats the response as a rejected key when that text contains `invalid` and either `api key` or `apikey`.

An empty page from `get_all_cves`, `get_cve_by_date`, `get_cve_by_cpe`, or any CPE Match method is success. `total_results == 0`.

## Attributes

| Exception | Attributes |
| --- | --- |
| `InvalidDateFormatError` | `date_str`, `message` |
| `InvalidParametersError` | `missing_params`, `message` |
| `InvalidCVEIDError` | `cve_id`, `message` |
| `NvdApiError`, `NvdRateLimitError`, `NvdNotFoundError` | `status_code`, `url` |
| `NvdResponseError` | the exception message only |
| `ValueError` | the exception message only |

`str(InvalidCVEIDError(...))` is `{cve_id} -> {message}`. `str(InvalidDateFormatError(...))` is `{date_str} -> {message}`. `str(InvalidParametersError(...))` names `missing_params` when that list is non-empty.
