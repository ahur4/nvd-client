"""Parameter checks and NVD timestamp formatting.

NVD date parameters use extended ISO-8601 with milliseconds
(``YYYY-MM-DDTHH:MM:SS.sss``) and an optional UTC offset. A positive offset
must be sent as ``%2B`` rather than a raw ``+``. This module formats the
timestamp; ``requests`` percent-encodes it when the value is passed as a
query parameter.
"""

import re
from datetime import datetime, timedelta, timezone

from nvd_client.exceptions import InvalidCVEIDError, InvalidDateFormatError, InvalidParametersError

MAX_DATE_RANGE = timedelta(days=120)
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def format_nvd_datetime(value: datetime) -> str:
    """Format ``value`` as an NVD timestamp in UTC.

    Naive values are treated as UTC. Aware values, including those built
    with :mod:`zoneinfo`, are converted to UTC. The ``+00:00`` suffix is
    intentional: callers must not paste it into a URL by hand.
    """
    if not isinstance(value, datetime):
        raise InvalidDateFormatError(value)
    utc_value = _as_utc(value)
    millis = utc_value.microsecond // 1000
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}+00:00"


def validate_and_convert_dates(
    start_date: datetime | None,
    end_date: datetime | None,
    param_names: list[str],
) -> tuple[str | None, str | None]:
    """Validate a date pair and return NVD timestamp strings.

    Both ends are required when either one is set. The span cannot exceed
    120 days, which is NVD's maximum for every date-range parameter.
    """
    if start_date is None and end_date is None:
        return None, None
    if start_date is None or end_date is None:
        raise InvalidParametersError(missing_params=param_names)
    if not isinstance(start_date, datetime) or not isinstance(end_date, datetime):
        invalid = start_date if not isinstance(start_date, datetime) else end_date
        raise InvalidDateFormatError(invalid)

    start_utc = _as_utc(start_date)
    end_utc = _as_utc(end_date)
    if end_utc < start_utc:
        raise InvalidParametersError(message="The end date must be on or after the start date.")
    if end_utc - start_utc > MAX_DATE_RANGE:
        raise InvalidParametersError(
            message="NVD allows a maximum date range of 120 consecutive days.",
        )
    return format_nvd_datetime(start_date), format_nvd_datetime(end_date)


def validate_cve_id(cve_id: str) -> bool:
    """Return ``True`` when ``cve_id`` matches ``CVE-YYYY-NNNN``.

    Raises :class:`~nvd_client.exceptions.InvalidCVEIDError` otherwise.
    """
    if isinstance(cve_id, str) and _CVE_ID_PATTERN.fullmatch(cve_id):
        return True
    raise InvalidCVEIDError(str(cve_id))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
