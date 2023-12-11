import requests

from .endpoints import BASE_URL


class CVEClient:
    """
    Working with CVE API
    """

    def __init__(self, api_key, helper, header):
        """
        Initialize CVE API with necessary configurations
        :param api_key: API key in string
        :param helper: OCTI helper
        :param header:
        """
        headers = {"Bearer": api_key, "User-Agent": header}
        self.token = api_key
        self.helper = helper
        self.session = requests.Session()
        self.session.headers.update(headers)

    @staticmethod
    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            info_msg = f"[API] HTTP Get Request to endpoint for path ({api_url})"
            self.helper.log_info(info_msg)

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = f"[API] Error while fetching data from {api_url}: {str(err)}"
            self.helper.log_error(error_msg)
            return None

    def get_complete_collection(self, cve_params=None):
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param cve_params: Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            response = self._request_data(self, BASE_URL, params=cve_params)

            if response is None:
                raise Exception("[API] Cannot get any data from API...")
            else:
                cve_collection = response.json()
                return cve_collection

        except Exception as err:
            self.helper.log_error(err)
            return
