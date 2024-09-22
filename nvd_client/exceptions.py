from typing import List


class InvalidDateFormatError(Exception):
    """Exception raised for errors in the input date format."""

    def __init__(self, date_str, message="Invalid date format. date type must be datetime obj."):
        self.date_str = date_str
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.date_str} -> {self.message}'


class InvalidParametersError(Exception):
    """Exception raised for invalid parameters."""

    def __init__(
            self,
            missing_params: List[str],
            message="Invalid parameter combination. Both parameters are required."
    ):
        self.missing_params = missing_params
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'Missing or incomplete parameters: {", ".join(self.missing_params)} -> {self.message}'


class InvalidCVEIDError(Exception):
    """Exception raised for errors in the input CVE ID."""
    def __init__(self, cve_id: str, message="Invalid CVE ID format. Please use CVE-YYYY-NNNN format."):
        self.cve_id = cve_id
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.cve_id} -> {self.message}'