import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_entities(self) -> list[str]:
        """
        :return: A list of dicts of the complete collection of subnet addresses
        :return: A list of dicts of the complete collection of subnet addresses
        """
        try:
            response = requests.get(self.config.api_base_url)

            if response.status_code != 200:
                raise Exception(
                    f"Failed to fetch data. HTTP Status: {response.status_code}"
                )

            lines = response.text.strip().splitlines()
            result = []

            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue  # skip comments and empty lines
                parts = line.split("\t")
                if len(parts) >= 3:
                    ip = parts[0]
                    subnet = parts[2]
                    result.append(f"{ip}/{subnet}")

            return result
        except Exception as err:
            self.helper.connector_logger.error(err)
