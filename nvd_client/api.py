import requests
from typing import Dict, List, Optional, Union
from utils import validate_and_convert_dates, validate_cve_id
from logger import setup_logger


class NvdApi:
    """
    A class to interact with the NVD API for fetching CVE data.

    Attributes:
        api_key (Optional[str]): The API key for authenticating requests.
        base_url (str): The base URL for the NVD API.
        logger (logging.Logger): Logger for the class.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        """
        Initialize the NvdApi class.

        Args:
            api_key (Optional[str]): The API key for authenticating requests. Default is None.
        """
        self.api_key: Optional[str] = api_key
        self.base_url: str = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.logger = setup_logger('nvd_client', 'nvd_client.log')

    def __str__(self) -> str:
        """
        Return a string representation of the NvdApi class.

        Returns:
            str: A string representation of the class.
        """
        return "What are you looking for?"

    @staticmethod
    def _verifier(params: Dict[str, Union[str, int]]) -> str:
        """
        Construct query string from parameters dictionary.

        Args:
            params (Dict[str, Union[str, int]]): The parameters' dictionary.

        Returns:
            str: The query string constructed from the parameters.
        """
        return "&".join([f"{k}={v}" for k, v in params.items()])

    def _make_request(
            self, params: Optional[Dict[str, Union[str, int]]] = None
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Make a request to the NVD API with the provided parameters.

        Args:
            params (Optional[Dict[str, Union[str, int]]]): The parameters for the API request. Default is None.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        try:
            parameters = self._verifier(params or {})
            link = f"{self.base_url}?{parameters}"
            headers = {'apiKey': self.api_key} if self.api_key else {}
            self.logger.info(f"Making request to {link}")
            response = requests.get(link, headers=headers)
            response.raise_for_status()
            self.logger.info(f"Request successful: {response.status_code}")
            return response.json()
        except requests.exceptions.Timeout as e:
            self.logger.error(f"Timeout error: {e}")
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error: {e}")
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error occurred: {e}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
        return None

    def get_all_cves(self, per_page: int = 2000, offset: int = 0) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch all CVEs with pagination.

        Args:
            per_page (int): The number of results per page. Default is 2000.
            offset (int): The starting index for the results. Default is 0.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        parameters = {
            'resultsPerPage': per_page,
            'startIndex': offset
        }
        return self._make_request(params=parameters)

    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch a CVE by its ID.

        Args:
            cve_id (str): The CVE ID to fetch.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        if validate_cve_id(cve_id):
            parameters = {"cveId": cve_id}
            return self._make_request(params=parameters)

    def get_cve_by_date(
            self,
            per_page: int = 2000,
            offset: int = 0,
            publish_start_date: Optional[str] = None,
            publish_end_date: Optional[str] = None,
            modify_start_date: Optional[str] = None,
            modify_end_date: Optional[str] = None,
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch CVEs by publication or modification date.

        Args:
            per_page (int): The number of results per page. Default is 2000.
            offset (int): The starting index for the results. Default is 0.
            publish_start_date (Optional[str]): The start date for the publication date range. Default is None.
            publish_end_date (Optional[str]): The end date for the publication date range. Default is None.
            modify_start_date (Optional[str]): The start date for the modification date range. Default is None.
            modify_end_date (Optional[str]): The end date for the modification date range. Default is None.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        parameters: Dict[str, Union[str, int, List, Dict]] = {}

        publish_start_date, publish_end_date = validate_and_convert_dates(
            start_date=publish_start_date,
            end_date=publish_end_date,
            param_names=["publish_start_date", "publish_end_date"]
        )

        modify_start_date, modify_end_date = validate_and_convert_dates(
            start_date=modify_start_date,
            end_date=modify_end_date,
            param_names=["modify_start_date", "modify_end_date"]
        )

        if publish_start_date and publish_end_date:
            parameters.update(pubStartDate=publish_start_date, pubEndDate=publish_end_date)

        if modify_start_date and modify_end_date:
            parameters.update(lastModStartDate=modify_start_date, lastModEndDate=modify_end_date)

        # Add more parameters as needed
        parameters.update(resultsPerPage=per_page, startIndex=offset)

        return self._make_request(params=parameters)

    def get_cve_by_cpe(
            self,
            cpe_name: str,
            per_page: int = 2000,
            offset: int = 0,
            publish_start_date: Optional[str] = None,
            publish_end_date: Optional[str] = None,
            modify_start_date: Optional[str] = None,
            modify_end_date: Optional[str] = None
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch CVEs by CpeId.

        Args:
            cpe_name (str): The CPE name to fetch.
            per_page (int): The number of results per page. Default is 2000.
            offset (int): The starting index for the results. Default is 0.
            publish_start_date (Optional[str]): The start date for the publication date range. Default is None.
            publish_end_date (Optional[str]): The end date for the publication date range. Default is None.
            modify_start_date (Optional[str]): The start date for the modification date range. Default is None.
            modify_end_date (Optional[str]): The end date for the modification date range. Default is None.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        parameters = {}

        publish_start_date, publish_end_date = validate_and_convert_dates(
            start_date=publish_start_date,
            end_date=publish_end_date,
            param_names=["publish_start_date", "publish_end_date"]
        )

        modify_start_date, modify_end_date = validate_and_convert_dates(
            start_date=modify_start_date,
            end_date=modify_end_date,
            param_names=["modify_start_date", "modify_end_date"]
        )

        if publish_start_date and publish_end_date:
            parameters.update(pubStartDate=publish_start_date, pubEndDate=publish_end_date)

        if modify_start_date and modify_end_date:
            parameters.update(lastModStartDate=modify_start_date, lastModEndDate=modify_end_date)

        parameters.update(resultsPerPage=per_page, startIndex=offset, cpeName=cpe_name)

        return self._make_request(params=parameters)
