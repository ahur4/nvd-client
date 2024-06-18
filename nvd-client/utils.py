import re
from datetime import datetime
from exceptions import InvalidDateFormatError, InvalidParametersError, InvalidCVEIDError
from typing import Optional, List


def validate_date_format(date_str):
    # Define the regex pattern for YYYY-MM-DD format
    pattern = r'^\d{4}-\d{2}-\d{2}$'
    # Check if the date_str matches the pattern
    if re.match(pattern, date_str):
        try:
            # Try to parse the date to ensure it's a valid date
            datetime.strptime(date_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False
    else:
        return False


def convert_date_to_iso(date_str):
    if validate_date_format(date_str):
        # Parse the input date
        date = datetime.strptime(date_str, '%Y-%m-%d')
        # Convert to the desired format
        iso_format_date = date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
        return iso_format_date
    else:
        raise InvalidDateFormatError(date_str)


def validate_and_convert_dates(start_date: Optional[str], end_date: Optional[str], param_names: List[str]):
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
