from typing import Dict, List, Optional, Union

import requests

from nvd_client.utils import validate_and_convert_dates, validate_cve_id


class NvdApi:
    """
    A class to interact with the NVD API for fetching CVE data.

    Attributes:
        api_key (Optional[str]): The API key for authenticating requests.
        api_key (Optional[str]): The Socks5 Proxy.
    """

    def __init__(self, api_key: Optional[str] = None, proxy: Optional[str] = None) -> None:
        """
        Initialize the NvdApi class.

        Args:
            api_key (Optional[str]): The API key for authenticating requests. Default is None.
            api_key (Optional[str]): The Socks5 Proxy.
        """
        self.proxy: Optional[str] = proxy
        self.api_key: Optional[str] = api_key
        self.base_url_cve: str = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.base_url_cpe: str = 'https://services.nvd.nist.gov/rest/json/cpematch/2.0'

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
            self,
            params: Optional[Dict[str, Union[str, int]]] = None,
            type_of: str = "cve",
            proxy: Optional[str] = None,
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Make a request to the NVD API with the provided parameters.

        Args:
            params (Optional[Dict[str, Union[str, int]]]): The parameters for the API request. Default is None.
            type_of (str): The parameters for the type of used api. default is cve.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        try:
            parameters = self._verifier(params or {})
            if type_of == "cve":
                link = f"{self.base_url_cve}?{parameters}"
            else:
                link = f"{self.base_url_cpe}?{parameters}"
            headers = {'apiKey': self.api_key} if self.api_key else {}
            if self.proxy:
                response = requests.get(link, headers=headers, proxies={"http": self.proxy, "https": self.proxy})
            elif proxy:
                response = requests.get(link, headers=headers, proxies={"http": proxy, "https": proxy})
            else:
                response = requests.get(link, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return None

    def get_all_cves(self, per_page: int = 2000, offset: int = 0, proxy: Optional[str] = None) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch all CVEs with pagination.

        Args:
            per_page (int): The number of results per page. Default is 2000.
            offset (int): The starting index for the results. Default is 0.
            proxy (str): The proxy to use. Default is None.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        parameters = {
            'resultsPerPage': per_page,
            'startIndex': offset
        }
        if proxy:
            return self._make_request(params=parameters, proxy=proxy)
        return self._make_request(params=parameters)

    def get_cve_by_id(self, cve_id: str, proxy: Optional[str] = None) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch a CVE by its ID.

        Args:
            cve_id (str): The CVE ID to fetch.
            proxy (str): The proxy to use. Default is None.

        Returns: Optional[Dict[str, Union[str, int, List, Dict]]]: The JSON response from the API, or None if an
        error occurred.
        """
        if validate_cve_id(cve_id):
            parameters = {"cveId": cve_id}
            if proxy:
                return self._make_request(params=parameters, proxy=proxy)
            return self._make_request(params=parameters)

    def get_cve_by_date(
            self,
            per_page: int = 2000,
            offset: int = 0,
            publish_start_date: Optional[str] = None,
            publish_end_date: Optional[str] = None,
            modify_start_date: Optional[str] = None,
            modify_end_date: Optional[str] = None,
            proxy: Optional[str] = None,
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
            proxy (str): The proxy to use. Default is None.

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

        if proxy:
            return self._make_request(params=parameters, proxy=proxy)
        return self._make_request(params=parameters)

    def get_cve_by_cpe(
            self,
            cpe_name: str,
            per_page: int = 2000,
            offset: int = 0,
            publish_start_date: Optional[str] = None,
            publish_end_date: Optional[str] = None,
            modify_start_date: Optional[str] = None,
            modify_end_date: Optional[str] = None,
            proxy: Optional[str] = None,
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
            proxy (str): The proxy to use. Default is None.

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

        if proxy:
            return self._make_request(params=parameters, proxy=proxy)
        return self._make_request(params=parameters)

    def get_cpes_by_cve(
            self,
            cve_id: str,
            per_page: int = 500,
            offset: int = 0,
            proxy: Optional[str] = None,
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch CPEs by CveId.

        Args:
            cve_id (str): The CVE ID to fetch.
            per_page (int): The number of results per page. Default and Maximum is 500.
            offset (int): The starting index for the results. Default is 0.
            proxy (str): The proxy to use. Default is None.

        Returns: List[Union[Dict[str, Any], Any]]: The JSON response from the API, or None if an
        error occurred.
        """
        if validate_cve_id(cve_id):
            parameters = {}
            parameters.update(resultsPerPage=per_page, startIndex=offset, cveId=cve_id)

            if proxy:
                return self._make_request(params=parameters, type_of="cpe", proxy=proxy)
            return self._make_request(params=parameters, type_of="cpe")

    def get_cpes_by_criteria(
            self,
            criteria: str,
            per_page: int = 500,
            offset: int = 0,
            proxy: Optional[str] = None,
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch CPEs by CveId.

        Args:
            criteria (str): The Criteria to fetch.
            per_page (int): The number of results per page. Default and Maximum is 500.
            offset (int): The starting index for the results. Default is 0.
            proxy (str): The proxy to use. Default is None.

        Returns: List[Union[Dict[str, Any], Any]]: The JSON response from the API, or None if an
        error occurred.
        """
        parameters = {}
        parameters.update(resultsPerPage=per_page, startIndex=offset, matchStringSearch=criteria)

        if proxy:
            return self._make_request(params=parameters, type_of="cpe", proxy=proxy)
        return self._make_request(params=parameters, type_of="cpe")

    def get_cpes_by_criteria_name_id(
            self,
            criteria_name_id: str,
            per_page: int = 500,
            offset: int = 0,
            proxy: Optional[str] = None,
    ) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
        """
        Fetch CPEs by CveId.

        Args:
            criteria_name_id (str): The Criteria Name ID to fetch.
            per_page (int): The number of results per page. Default and Maximum is 500.
            offset (int): The starting index for the results. Default is 0.
            proxy (str): The proxy to use. Default is None.

        Returns: List[Union[Dict[str, Any], Any]]: The JSON response from the API, or None if an
        error occurred.
        """
        parameters = {}
        parameters.update(resultsPerPage=per_page, startIndex=offset, matchCriteriaId=criteria_name_id)

        if proxy:
            return self._make_request(params=parameters, type_of="cpe", proxy=proxy)
        return self._make_request(params=parameters, type_of="cpe")
