import re
from datetime import datetime
from typing import Optional, List

import pytz

from nvd_client.exceptions import InvalidDateFormatError, InvalidParametersError, InvalidCVEIDError

# Use Iran's timezone
IRAN_TZ = pytz.timezone('Asia/Tehran')


def validate_date_format(date_str: str):
    # Define the regex pattern for ISO 8601 format with timezone
    pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}$'
    # Check if the date_str matches the pattern
    if re.match(pattern, date_str):
        try:
            # Parse the date to ensure it's a valid date
            datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%f')
            return True
        except ValueError:
            return False
    return False


def convert_date_to_iso(date: datetime):
    if isinstance(date, datetime):
        # Convert to the desired ISO format without timezone information
        iso_format_date = date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]  # Truncate to milliseconds
        return iso_format_date
    else:
        raise InvalidDateFormatError(f"Invalid datetime object: {date}")


def validate_and_convert_dates(start_date: Optional[datetime], end_date: Optional[datetime], param_names: List[str]):
    if start_date and end_date:
        return convert_date_to_iso(start_date), convert_date_to_iso(end_date)
    elif start_date or end_date:
        raise InvalidParametersError(missing_params=param_names)
    return None, None


def validate_cve_id(cve_id: str) -> bool:
    # Define the regex pattern for CVE-YYYY-NNNN format
    pattern = r'^CVE-\d{4}-\d{4,}$'
    # Check if the cve_id matches the pattern
    if re.match(pattern, cve_id):
        return True
    else:
        raise InvalidCVEIDError(cve_id)
