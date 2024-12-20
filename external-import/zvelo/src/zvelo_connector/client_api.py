import json

import requests


class ConnectorClient:
    """
    Represent Zvelo API client interface.
    """

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # obtain oauth token
        self.base_api = "https://api.zvelo.io"
        self.token_api = "https://oauth.zvelo.io/oauth/token"
        self.access_token = self._get_authentication_token()

        # Define headers in session and update when needed
        headers = {"Authorization": "Bearer " + self.access_token}
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.collection_api = {
            "threat": "/v1/threat",
            "phish": "/v1/phish",
            "malicious": "/v1/malicious",
        }

    def _get_authentication_token(self) -> str:
        """
        Get a authentication token from Zvelo.
        :return: Authentication token
        """
        token_headers = {"Content-Type": "application/json"}
        data = {
            "client_id": self.config.zvelo_client_id,
            "client_secret": self.config.zvelo_client_secret,
            "audience": "https://api.zvelo.io/v1/",
            "grant_type": "client_credentials",
        }
        try:
            response = requests.post(self.token_api, headers=token_headers, json=data)
            response.raise_for_status()
        except Exception as err:
            error_msg = f"[API] Error while retrieving access token: {err}"
            self.helper.connector_logger.error(
                error_msg, {"url_path": {self.token_api}, "error": {str(err)}}
            )
            raise Exception(error_msg)

        response_data = json.loads(response.text)
        return response_data.get("access_token")

    @staticmethod
    def _extract_entities(response: dict, collection: str) -> list[dict]:
        """
        Extract collection's data from Zvelo response.
        :param response: Parsed JSON response
        :param collection: Name of collection to get data for
        :return: List of collection's entities
        """
        if collection == "threat":
            return response.get("threat_info").get("threat")
        if collection == "malicious":
            return response.get("malicious_info").get("malicious")
        if collection == "phish":
            return response.get("phish_info").get("phish")

    def get_collections_entities(self, collection: str, from_date: str) -> list[dict]:
        """
        Get collection's entities from Zvelo.
        :param collection: Name of collection to get entities for
        :param from_date: Minimum entity creation date timestamp
        :return: List of collection's entities
        """
        params = {"page": 0}
        if from_date:
            params["created_date_start"] = from_date

        collection_api = self.collection_api.get(collection)
        collection_api_url = self.base_api + collection_api
        has_more = True
        entries = []
        while has_more:
            try:
                response = self.session.get(url=collection_api_url, params=params)
                response.raise_for_status()
                response_data = response.json()
                max_page = response_data.get("_response_part").get("num_pages")
                entries.extend(self._extract_entities(response_data, collection))
                params["page"] += 1
                if params["page"] >= max_page:
                    has_more = False

            except requests.RequestException as err:
                error_msg = (
                    f"[API] Error while fetching data in collection '{collection}': "
                )
                self.helper.connector_logger.error(
                    error_msg, {"url_path": {collection_api_url}, "error": {str(err)}}
                )
                raise Exception(error_msg)

        return entries
