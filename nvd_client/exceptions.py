"""Errors raised by the NVD client."""


class NvdClientError(Exception):
    """Base class for every error raised by this package."""


class InvalidDateFormatError(NvdClientError):
    """A date argument was not a ``datetime``."""

    def __init__(
        self,
        date_str: object,
        message: str = "Dates must be datetime objects. Naive datetimes are treated as UTC.",
    ) -> None:
        self.date_str = date_str
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.date_str} -> {self.message}"


class InvalidParametersError(NvdClientError):
    """Query parameters are missing, incomplete, or outside NVD's limits."""

    def __init__(
        self,
        missing_params: list[str] | None = None,
        message: str = "Invalid parameter combination. Both parameters are required.",
    ) -> None:
        self.missing_params = list(missing_params or [])
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.missing_params:
            joined = ", ".join(self.missing_params)
            return f"Missing or incomplete parameters: {joined} -> {self.message}"
        return self.message


class InvalidCVEIDError(NvdClientError):
    """A CVE ID is not in ``CVE-YYYY-NNNN`` form (at least four digits)."""

    def __init__(
        self,
        cve_id: str,
        message: str = "Invalid CVE ID format. Use CVE-YYYY-NNNN (at least four digits).",
    ) -> None:
        self.cve_id = cve_id
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.cve_id} -> {self.message}"


class NvdApiError(NvdClientError):
    """The NVD service rejected a request or the connection failed."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        url: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(message)


class NvdRateLimitError(NvdApiError):
    """NVD returned 403 or 429 after retries were exhausted.

    NVD uses both status codes when a client exceeds the rolling rate limit
    (5 requests per 30 seconds without an API key, 50 with one).
    """


class NvdNotFoundError(NvdApiError):
    """The requested CVE or resource was not found."""


class NvdResponseError(NvdClientError):
    """The HTTP call succeeded but the body was not the expected NVD document."""
