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
    def _request_data(self, api_url, params=None):
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

    def get_complete_collection(self, start_index=None, results_per_page=None):
        """
        :return: A list of dicts of the complete collection of CVE
        """
        cve_params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
            "lastModStartDate": "2023-11-01T00:00:00",
            "lastModEndDate": "2023-12-31T23:59:59"
        }
        #TODO can only get data max range 120 days, send an error if wanted history

        response = self._request_data(self, BASE_URL, params=cve_params)

        cve_collection = response.json()

        return cve_collection

