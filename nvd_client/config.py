"""Client configuration.

NVD publishes two rolling windows (https://nvd.nist.gov/developers/start-here):

* without an API key, 5 requests in 30 seconds
* with an API key, 50 requests in 30 seconds

The default ``rate_limit_delay`` leaves one request's worth of that window
between calls (6 seconds, or 0.6 seconds when a key is set). Set the delay
yourself to slow down further. NIST also recommends sleeping for several
seconds between requests so bursts are not rejected.
"""

from dataclasses import dataclass

from nvd_client.version import __version__

MAX_CVE_RESULTS_PER_PAGE = 2000
MAX_CPE_RESULTS_PER_PAGE = 500
RATE_LIMIT_WINDOW_SECONDS = 30
RATE_LIMIT_REQUESTS_WITHOUT_KEY = 5
RATE_LIMIT_REQUESTS_WITH_KEY = 50

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json"
DEFAULT_USER_AGENT = f"nvd-client/{__version__} (+https://github.com/ahur4/nvd-client)"


def _require_int(name: str, value: int, low: int, high: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < low or (high is not None and value > high):
        if high is None:
            raise ValueError(f"{name} must be >= {low}")
        raise ValueError(f"{name} must be between {low} and {high}")


def _require_non_negative(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")


@dataclass(frozen=True, slots=True)
class NvdConfig:
    """Settings for :class:`nvd_client.api.NvdApi`.

    The object is frozen. Build a new config and a new client to change it.
    An empty ``api_key`` is stored as ``None``. Naive date values are not
    configured here; see :func:`nvd_client.utils.format_nvd_datetime`.

    ``timeout`` is passed to ``requests`` and may be a single seconds value
    or a ``(connect, read)`` pair. ``results_per_page`` is the CVE default
    (NVD's maximum is 2000). CPE Match calls use ``cpe_results_per_page``
    (NVD's maximum is 500).

    ``max_retries`` is the number of additional attempts after the first
    request. Retries cover connection errors and HTTP 403, 429, 500, 502,
    503, and 504. ``backoff_factor`` seconds grow as
    ``backoff_factor * 2**attempt``, capped by ``max_backoff``. A
    ``Retry-After`` header replaces that delay.
    """

    base_url: str = DEFAULT_BASE_URL
    api_key: str | None = None
    timeout: float | tuple[float, float] = 30.0
    results_per_page: int = MAX_CVE_RESULTS_PER_PAGE
    cpe_results_per_page: int = MAX_CPE_RESULTS_PER_PAGE
    rate_limit_delay: float | None = None
    max_retries: int = 4
    backoff_factor: float = 1.0
    max_backoff: float = 60.0
    user_agent: str = ""
    proxy: str | None = None

    def __post_init__(self) -> None:
        base_url = self.base_url.strip().rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        object.__setattr__(self, "base_url", base_url)

        api_key = self.api_key.strip() if isinstance(self.api_key, str) else None
        object.__setattr__(self, "api_key", api_key or None)

        self._validate_timeout()
        _require_int(
            "results_per_page",
            self.results_per_page,
            1,
            MAX_CVE_RESULTS_PER_PAGE,
        )
        _require_int(
            "cpe_results_per_page",
            self.cpe_results_per_page,
            1,
            MAX_CPE_RESULTS_PER_PAGE,
        )
        if self.rate_limit_delay is not None:
            _require_non_negative("rate_limit_delay", self.rate_limit_delay)
        _require_int("max_retries", self.max_retries, 0)
        _require_non_negative("backoff_factor", self.backoff_factor)
        _require_non_negative("max_backoff", self.max_backoff)

        user_agent = self.user_agent.strip() if isinstance(self.user_agent, str) else ""
        object.__setattr__(self, "user_agent", user_agent or DEFAULT_USER_AGENT)

        if self.proxy is None:
            return
        if not isinstance(self.proxy, str):
            raise ValueError("proxy must be a string URL or None")
        proxy = self.proxy.strip()
        object.__setattr__(self, "proxy", proxy or None)

    def _validate_timeout(self) -> None:
        timeout = self.timeout
        if isinstance(timeout, bool):
            raise ValueError("timeout must be a number of seconds or a (connect, read) pair")
        if isinstance(timeout, tuple):
            if len(timeout) != 2:
                raise ValueError("timeout tuple must be (connect_seconds, read_seconds)")
            for part in timeout:
                _require_non_negative("timeout", part)
                if part <= 0:
                    raise ValueError("timeout values must be greater than 0")
            return
        _require_non_negative("timeout", timeout)
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")

    @property
    def effective_rate_limit_delay(self) -> float:
        """Seconds to wait between HTTP calls.

        An explicit ``rate_limit_delay`` wins. Otherwise the delay is the
        published window divided by the allowed number of requests.
        """
        if self.rate_limit_delay is not None:
            return self.rate_limit_delay
        requests_allowed = (
            RATE_LIMIT_REQUESTS_WITH_KEY if self.api_key else RATE_LIMIT_REQUESTS_WITHOUT_KEY
        )
        return RATE_LIMIT_WINDOW_SECONDS / requests_allowed
