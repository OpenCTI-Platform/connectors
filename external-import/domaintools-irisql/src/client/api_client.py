import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class DomainToolsClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: str):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (str): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper
        self.base_url = base_url
        # Define headers in session and update when needed
        headers = {"x-api-key": api_key, "Content-Type": "text/plain"}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None, body=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """        
        try:
            
            response = self.session.post(api_url, params=params, data=body)
            self.helper.connector_logger.info("[API] HTTP Get Request to endpoint", {"url_path": api_url})

            response.raise_for_status()
            return response           

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_entities(self, body=None) -> list:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================
            result_data = []
            params = { }
            while True:                
                response = self._request_data(self.base_url, params=params, body=body)
                response.raise_for_status()                
                
                json_response = response.json()   
                current_results = json_response['response']['results']
                result_data.extend(current_results)
                
                if not json_response['response']['has_more_results']: break
                
                # Update the 'position' field for pagination
                params['position'] = json_response['response']['position'] 
            
            return result_data

            # return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

            raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
