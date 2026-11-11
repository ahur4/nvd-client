"""Typed client for the NVD CVE and CPE Match APIs (version 2.0)."""

from nvd_client.api import NvdApi
from nvd_client.config import NvdConfig
from nvd_client.exceptions import (
    InvalidCVEIDError,
    InvalidDateFormatError,
    InvalidParametersError,
    NvdApiError,
    NvdClientError,
    NvdNotFoundError,
    NvdRateLimitError,
    NvdResponseError,
)
from nvd_client.models import CpeMatchResponse, CveListResponse, CveRecord
from nvd_client.version import __version__

__author__ = "Ahur4"
__author_email__ = "ahur4.rahmani@gmail.com"
__license__ = "MIT"
__copyright__ = "Copyright 2024, Ahur4"

__all__ = [
    "CpeMatchResponse",
    "CveListResponse",
    "CveRecord",
    "InvalidCVEIDError",
    "InvalidDateFormatError",
    "InvalidParametersError",
    "NvdApi",
    "NvdApiError",
    "NvdClientError",
    "NvdConfig",
    "NvdNotFoundError",
    "NvdRateLimitError",
    "NvdResponseError",
    "__version__",
]
