"""HTTP client for the NVD CVE and CPE Match 2.0 APIs.

CVE methods that return a collection produce a :class:`CveListResponse`.
:meth:`NvdApi.get_cve_by_id` returns the single :class:`CveRecord` and raises
:class:`~nvd_client.exceptions.NvdNotFoundError` when NVD has no such CVE.
CPE Match methods return a :class:`CpeMatchResponse`.

Transport failures, HTTP errors, and rate limits raise
:class:`~nvd_client.exceptions.NvdApiError` (or a subclass). They do not come
back as ``None``. A query that matches nothing is a normal page whose
``total_results`` is ``0``.
"""

import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TypeVar, cast

import requests
from pydantic import ValidationError

from nvd_client.config import (
    MAX_CPE_RESULTS_PER_PAGE,
    MAX_CVE_RESULTS_PER_PAGE,
    NvdConfig,
)
from nvd_client.exceptions import (
    InvalidParametersError,
    NvdApiError,
    NvdNotFoundError,
    NvdRateLimitError,
    NvdResponseError,
)
from nvd_client.models import CpeMatchResponse, CveListResponse, CveRecord, NvdModel
from nvd_client.utils import validate_and_convert_dates, validate_cve_id

_ModelT = TypeVar("_ModelT", bound=NvdModel)
_Params = dict[str, str | int]

# NVD answers rate-limit violations with 403 as well as 429, and sheds load
# with 503. The other 5xx codes are transient and worth one more try.
_RETRY_STATUSES = frozenset({403, 429, 500, 502, 503, 504})
_RATE_LIMIT_STATUSES = frozenset({403, 429})


class NvdApi:
    """Client for ``/rest/json/cves/2.0`` and ``/rest/json/cpematch/2.0``.

    ``NvdApi(api_key)`` and ``NvdApi(api_key, proxy)`` still work. Pass
    ``config`` for the rest of the knobs (base URL, timeouts, page size,
    rate-limit delay, retries, user agent). A non-``None`` ``api_key`` or
    ``proxy`` overrides the same field on ``config``.

    Per-call ``proxy`` overrides the client proxy for that request only.
    ``per_page=None`` uses the page size on the config.

    The client sleeps between requests so a single instance stays inside
    NVD's published rate limit. It is safe to share across threads; calls
    take turns. Use the client as a context manager to close the connection
    pool.
    """

    def __init__(
        self,
        api_key: str | None = None,
        proxy: str | None = None,
        *,
        config: NvdConfig | None = None,
    ) -> None:
        base = config if config is not None else NvdConfig()
        if api_key is None and proxy is None:
            self.config = base
        else:
            self.config = NvdConfig(
                base_url=base.base_url,
                api_key=base.api_key if api_key is None else api_key,
                timeout=base.timeout,
                results_per_page=base.results_per_page,
                cpe_results_per_page=base.cpe_results_per_page,
                rate_limit_delay=base.rate_limit_delay,
                max_retries=base.max_retries,
                backoff_factor=base.backoff_factor,
                max_backoff=base.max_backoff,
                user_agent=base.user_agent,
                proxy=base.proxy if proxy is None else proxy,
            )
        self._session = requests.Session()
        self._sleep: Callable[[float], None] = time.sleep
        self._monotonic: Callable[[], float] = time.monotonic
        self._last_request: float | None = None
        self._lock = threading.Lock()
        self._apply_headers()

    def __repr__(self) -> str:
        return self._summary()

    def __str__(self) -> str:
        return self._summary()

    def __enter__(self) -> "NvdApi":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._session.close()

    def get_all_cves(
        self,
        per_page: int | None = None,
        offset: int = 0,
        proxy: str | None = None,
    ) -> CveListResponse:
        """Fetch one page of CVEs, ordered as NVD returns them."""
        params = self._paged(
            per_page,
            offset,
            maximum=MAX_CVE_RESULTS_PER_PAGE,
            default=self.config.results_per_page,
        )
        return self._cve_page(params, proxy)

    def get_cve_by_id(self, cve_id: str, proxy: str | None = None) -> CveRecord:
        """Fetch one CVE by id.

        Raises :class:`~nvd_client.exceptions.InvalidCVEIDError` for a bad id
        and :class:`~nvd_client.exceptions.NvdNotFoundError` when NVD has no
        record.
        """
        validate_cve_id(cve_id)
        page = self._cve_page({"cveId": cve_id}, proxy)
        if not page.cves:
            raise NvdNotFoundError(
                f"No CVE found for {cve_id}",
                status_code=200,
                url=self._url("cves/2.0"),
            )
        return page.cves[0]

    def get_cve_by_date(
        self,
        per_page: int | None = None,
        offset: int = 0,
        publish_start_date: datetime | None = None,
        publish_end_date: datetime | None = None,
        modify_start_date: datetime | None = None,
        modify_end_date: datetime | None = None,
        proxy: str | None = None,
    ) -> CveListResponse:
        """Fetch CVEs published and/or modified inside a date range.

        Each range needs both ends and must be at most 120 days. Naive
        datetimes are UTC. Aware datetimes are converted to UTC.
        """
        params = self._paged(
            per_page,
            offset,
            maximum=MAX_CVE_RESULTS_PER_PAGE,
            default=self.config.results_per_page,
        )
        self._add_dates(
            params,
            publish_start_date,
            publish_end_date,
            modify_start_date,
            modify_end_date,
        )
        return self._cve_page(params, proxy)

    def get_cve_by_cpe(
        self,
        cpe_name: str,
        per_page: int | None = None,
        offset: int = 0,
        publish_start_date: datetime | None = None,
        publish_end_date: datetime | None = None,
        modify_start_date: datetime | None = None,
        modify_end_date: datetime | None = None,
        proxy: str | None = None,
    ) -> CveListResponse:
        """Fetch CVEs whose applicability statement matches ``cpe_name``.

        ``cpe_name`` is sent as the ``cpeName`` parameter. NVD compares it
        with the CPE match criteria on each CVE. The part, vendor, product,
        and version components must be real values, not ``*``.
        """
        if not isinstance(cpe_name, str) or not cpe_name.strip():
            raise InvalidParametersError(message="cpe_name is required.")
        params = self._paged(
            per_page,
            offset,
            maximum=MAX_CVE_RESULTS_PER_PAGE,
            default=self.config.results_per_page,
        )
        params["cpeName"] = cpe_name.strip()
        self._add_dates(
            params,
            publish_start_date,
            publish_end_date,
            modify_start_date,
            modify_end_date,
        )
        return self._cve_page(params, proxy)

    def get_cpes_by_cve(
        self,
        cve_id: str,
        per_page: int | None = None,
        offset: int = 0,
        proxy: str | None = None,
    ) -> CpeMatchResponse:
        """Fetch CPE match strings associated with a CVE id."""
        validate_cve_id(cve_id)
        params = self._paged(
            per_page,
            offset,
            maximum=MAX_CPE_RESULTS_PER_PAGE,
            default=self.config.cpe_results_per_page,
        )
        params["cveId"] = cve_id
        return self._cpe_page(params, proxy)

    def get_cpes_by_criteria(
        self,
        criteria: str,
        per_page: int | None = None,
        offset: int = 0,
        proxy: str | None = None,
    ) -> CpeMatchResponse:
        """Fetch CPE match strings for a ``matchStringSearch`` value."""
        if not isinstance(criteria, str) or not criteria.strip():
            raise InvalidParametersError(message="criteria is required.")
        params = self._paged(
            per_page,
            offset,
            maximum=MAX_CPE_RESULTS_PER_PAGE,
            default=self.config.cpe_results_per_page,
        )
        params["matchStringSearch"] = criteria.strip()
        return self._cpe_page(params, proxy)

    def get_cpes_by_criteria_name_id(
        self,
        criteria_name_id: str,
        per_page: int | None = None,
        offset: int = 0,
        proxy: str | None = None,
    ) -> CpeMatchResponse:
        """Fetch the CPE match string for a ``matchCriteriaId`` UUID."""
        if not isinstance(criteria_name_id, str) or not criteria_name_id.strip():
            raise InvalidParametersError(message="criteria_name_id is required.")
        params = self._paged(
            per_page,
            offset,
            maximum=MAX_CPE_RESULTS_PER_PAGE,
            default=self.config.cpe_results_per_page,
        )
        params["matchCriteriaId"] = criteria_name_id.strip()
        return self._cpe_page(params, proxy)

    def _summary(self) -> str:
        key_state = "set" if self.config.api_key else "unset"
        return f"NvdApi(base_url={self.config.base_url!r}, api_key={key_state})"

    def _apply_headers(self) -> None:
        self._session.headers["User-Agent"] = self.config.user_agent
        if self.config.api_key:
            self._session.headers["apiKey"] = self.config.api_key
        else:
            self._session.headers.pop("apiKey", None)

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}/{path.lstrip('/')}"

    def _proxies(self, proxy: str | None) -> dict[str, str] | None:
        chosen = self.config.proxy if proxy is None else proxy
        if chosen is None:
            return None
        if not isinstance(chosen, str) or not chosen.strip():
            raise InvalidParametersError(message="proxy must be a non-empty URL string.")
        url = chosen.strip()
        return {"http": url, "https": url}

    def _paged(
        self,
        per_page: int | None,
        offset: int,
        *,
        maximum: int,
        default: int,
    ) -> _Params:
        size = default if per_page is None else per_page
        if isinstance(size, bool) or not isinstance(size, int):
            raise InvalidParametersError(message="per_page must be an integer.")
        if not 1 <= size <= maximum:
            raise InvalidParametersError(message=f"per_page must be between 1 and {maximum}.")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise InvalidParametersError(message="offset must be an integer >= 0.")
        return {"resultsPerPage": size, "startIndex": offset}

    def _add_dates(
        self,
        params: _Params,
        publish_start_date: datetime | None,
        publish_end_date: datetime | None,
        modify_start_date: datetime | None,
        modify_end_date: datetime | None,
    ) -> None:
        publish_start, publish_end = validate_and_convert_dates(
            start_date=publish_start_date,
            end_date=publish_end_date,
            param_names=["publish_start_date", "publish_end_date"],
        )
        modify_start, modify_end = validate_and_convert_dates(
            start_date=modify_start_date,
            end_date=modify_end_date,
            param_names=["modify_start_date", "modify_end_date"],
        )
        if publish_start is not None and publish_end is not None:
            params["pubStartDate"] = publish_start
            params["pubEndDate"] = publish_end
        if modify_start is not None and modify_end is not None:
            params["lastModStartDate"] = modify_start
            params["lastModEndDate"] = modify_end

    def _cve_page(self, params: _Params, proxy: str | None) -> CveListResponse:
        payload = self._request("cves/2.0", params, proxy)
        return _parse(CveListResponse, payload)

    def _cpe_page(self, params: _Params, proxy: str | None) -> CpeMatchResponse:
        payload = self._request("cpematch/2.0", params, proxy)
        return _parse(CpeMatchResponse, payload)

    def _request(self, path: str, params: _Params, proxy: str | None) -> object:
        url = self._url(path)
        proxies = self._proxies(proxy)
        self._apply_headers()
        last_status: int | None = None
        for attempt in range(self.config.max_retries + 1):
            self._wait_turn()
            try:
                response = self._send(url, params, proxies)
            except requests.RequestException as exc:
                if attempt >= self.config.max_retries:
                    raise NvdApiError(f"Request to {url} failed: {exc}", url=url) from exc
                self._sleep(self._backoff(attempt, retry_after=None))
                continue

            last_status = response.status_code
            if response.status_code == 404:
                raise NvdNotFoundError(_error_message(response), status_code=404, url=url)
            if response.status_code in _RETRY_STATUSES and not _is_auth_failure(response):
                if attempt >= self.config.max_retries:
                    message = _error_message(response)
                    error_type = (
                        NvdRateLimitError
                        if response.status_code in _RATE_LIMIT_STATUSES
                        else NvdApiError
                    )
                    raise error_type(message, status_code=response.status_code, url=url)
                self._sleep(self._backoff(attempt, retry_after=_retry_after_seconds(response)))
                continue
            if response.status_code >= 400:
                raise NvdApiError(
                    _error_message(response),
                    status_code=response.status_code,
                    url=url,
                )
            try:
                return cast(object, response.json())
            except ValueError as exc:
                raise NvdResponseError(
                    f"NVD response from {url} was not JSON.",
                ) from exc
        raise NvdApiError(
            f"Request to {url} failed with HTTP {last_status}.",
            status_code=last_status,
            url=url,
        )

    def _send(
        self,
        url: str,
        params: _Params,
        proxies: Mapping[str, str] | None,
    ) -> requests.Response:
        if proxies is None:
            return self._session.get(url, params=params, timeout=self.config.timeout)
        return self._session.get(
            url,
            params=params,
            timeout=self.config.timeout,
            proxies=dict(proxies),
        )

    def _wait_turn(self) -> None:
        delay = self.config.effective_rate_limit_delay
        if delay <= 0:
            return
        with self._lock:
            now = self._monotonic()
            if self._last_request is not None:
                remaining = delay - (now - self._last_request)
                if remaining > 0:
                    self._sleep(remaining)
            self._last_request = self._monotonic()

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return max(0.0, retry_after)
        # ``int ** int`` is typed as Any. A float base keeps this a float.
        grown = self.config.backoff_factor * (2.0**attempt)
        return min(self.config.max_backoff, grown)


def _parse(model: type[_ModelT], payload: object) -> _ModelT:
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise NvdResponseError(
            f"NVD response did not match {model.__name__} ({exc.error_count()} validation errors)."
        ) from exc


def _is_auth_failure(response: requests.Response) -> bool:
    """True when a 403 is an API-key rejection rather than a rate limit.

    NVD uses 403 for both. Retrying a rejected key only burns the limit.
    """
    if response.status_code not in {401, 403}:
        return False
    header_message = response.headers.get("message", "")
    body = response.text[:500] if response.text else ""
    message = f"{header_message} {body}".lower()
    return "invalid" in message and ("api key" in message or "apikey" in message)


def _retry_after_seconds(response: requests.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.timestamp() - time.time()


def _error_message(response: requests.Response) -> str:
    parts = [f"NVD request failed with HTTP {response.status_code}"]
    header_message = response.headers.get("message")
    if header_message:
        parts.append(str(header_message))
    text = " ".join(response.text.split()) if response.text else ""
    if text:
        if len(text) > 300:
            text = text[:300] + "..."
        parts.append(text)
    return ": ".join(parts)
