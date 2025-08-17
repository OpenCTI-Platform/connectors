import gzip
import json
from io import BytesIO
from typing import List, Optional

import requests
from requests.exceptions import HTTPError, RequestException

from .models import C2


class ConnectorClient:
    """
    A client for interacting with an API.

    This class handles making HTTP requests to an API, including authentication
    and error handling, and processes the API responses.

    Attributes:
        helper: A helper object for logging and utilities.
        config: A configuration object containing API details.
        session: An HTTP session for making requests with pre-configured headers.
    """

    def __init__(self, helper, config):
        """
        Initialize the ConnectorClient with necessary configurations.
        """
        self.helper = helper
        self.config = config

        # Set up session with default headers
        self.session = requests.Session()
        self.session.headers.update({"token": self.config.api_key})

    def _request_data(
        self, api_url: str, params: Optional[dict] = None
    ) -> requests.Response:
        """
        Sends a GET request to the specified API URL.

        Args:
            api_url (str): The URL to send the request to.
            params (dict, optional): Query parameters for the request.

        Returns:
            requests.Response: The HTTP response object.

        Raises:
            HTTPError: If an HTTP error occurs.
            RequestException: If a request-related error occurs.
        """

        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP GET Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except HTTPError as http_err:
            self.helper.connector_logger.error(
                "[API] HTTP error occurred",
                {"url_path": api_url, "error": str(http_err)},
            )
            raise
        except RequestException as req_err:
            self.helper.connector_logger.error(
                "[API] Request error occurred",
                {"url_path": api_url, "error": str(req_err)},
            )
            raise
        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Unexpected error occurred",
                {"url_path": api_url, "error": str(err)},
            )
            raise

    def get_entities(self, params: Optional[dict] = None) -> Optional[List[C2]]:
        """
        Fetches and processes entities from the API.

        Args:
            params (dict, optional): Query parameters for the API request.

        Returns:
            list[dict] or None: A list of entities if successful, or None if an error occurs.
        """
        try:
            response = self._request_data(self.config.api_base_url, params=params)

            # Decompress and decode the response content
            with gzip.GzipFile(fileobj=BytesIO(response.content)) as gzipped_file:
                raw_data = gzipped_file.read().decode("utf-8")

            # Parse each line of the raw data as JSON
            entities: List[C2] = []
            for line in raw_data.splitlines():
                if line.strip():
                    try:
                        entities.append(json.loads(line))
                    except json.JSONDecodeError:
                        self.helper.connector_logger.warning(
                            "Skipping invalid JSON line: %s", line
                        )

            return entities

        except HTTPError as http_err:
            self.helper.connector_logger.error(
                "HTTP error while retrieving entities: %s", http_err
            )
        except RequestException as req_err:
            self.helper.connector_logger.error(
                "Request error while retrieving entities: %s", req_err
            )
        except Exception as err:
            self.helper.connector_logger.error(
                "Unexpected error while retrieving entities: %s", err
            )

        return None
