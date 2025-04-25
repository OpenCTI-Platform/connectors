import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {"Authorization": self.config.api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

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

    def get_entities(self, params=None) -> dict:
        """ """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================
            self.helper.connector_logger.info(
                "Fetching data from external source",
                {"url_path": self.config.api_base_url},
            )
            response = self._request_data(self.config.api_base_url, params=params)
            self.helper.connector_logger.info(
                "Response from external source",
                {"url_path": self.config.api_base_url, "response": response.text},
            )
            if response.status_code != 200:
                self.helper.connector_logger.error(
                    "Error while fetching data",
                    {
                        "url_path": self.config.api_base_url,
                        "status_code": response.status_code,
                    },
                )
                return None
            objects = response.json()["objects"]
            self.helper.connector_logger.info(
                "Successfully fetched data: " + str(len(objects)) + " objects",
                {
                    "url_path": self.config.api_base_url,
                    "status_code": response.status_code,
                },
            )
            return objects
            # ===========================
            # === Add your code above ===
            # ===========================

            raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
