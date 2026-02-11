import gzip
import json
import time
from io import BytesIO
from typing import TYPE_CHECKING, List, Optional

import requests
from external_import_connector.constants import (
    APIConstants,
    LoggingPrefixes,
    ProcessingLimits,
)
from external_import_connector.exceptions import (
    APIError,
    NonRetryableError,
    RetryableError,
)
from external_import_connector.models import C2
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectTimeout, HTTPError, ReadTimeout, RequestException
from urllib3.util.retry import Retry

if TYPE_CHECKING:
    from external_import_connector import ConfigLoader


class HTTPSessionManager:
    """Manages HTTP session configuration and lifecycle."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper

    def create_session(self, api_key: str) -> requests.Session:
        """Create a new HTTP session with resilience features."""
        session = requests.Session()
        session.headers.update({"token": api_key})

        # Configure retry strategy
        retry_strategy = Retry(
            total=APIConstants.RETRY_TOTAL,
            backoff_factor=APIConstants.RETRY_BACKOFF_FACTOR,
            status_forcelist=APIConstants.RETRY_STATUS_CODES,
            allowed_methods=APIConstants.RETRY_METHODS,
            raise_on_status=False,
        )

        # Create adapter with retry strategy
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=APIConstants.POOL_CONNECTIONS,
            pool_maxsize=APIConstants.POOL_MAXSIZE,
        )

        # Mount adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.HTTP_RESILIENCE} Created session with retry strategy: "
            f"{APIConstants.RETRY_TOTAL} retries, backoff_factor={APIConstants.RETRY_BACKOFF_FACTOR}, "
            f"pool_size={APIConstants.POOL_MAXSIZE}"
        )

        return session


class DataProcessor:
    """Processes raw API response data."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.latest_timestamp: Optional[str] = None

    def process_gzipped_response(self, response: requests.Response) -> List[C2]:
        """Process gzipped response content into C2 entities."""
        try:
            # Decompress and decode the response content
            with gzip.GzipFile(fileobj=BytesIO(response.content)) as gzipped_file:
                raw_data = gzipped_file.read().decode("utf-8")

            # Parse each line of the raw data as JSON
            all_entities: List[C2] = []
            latest_timestamp = None

            for line in raw_data.splitlines():
                if line.strip():
                    try:
                        entity_data = json.loads(line)
                        all_entities.append(entity_data)

                        # Track latest timestamp for next incremental run
                        entity_timestamp = entity_data.get("timestamp")
                        if entity_timestamp:
                            if (
                                not latest_timestamp
                                or entity_timestamp > latest_timestamp
                            ):
                                latest_timestamp = entity_timestamp

                    except json.JSONDecodeError:
                        self.helper.connector_logger.warning(
                            f"Skipping invalid JSON line: {line}"
                        )

            self.latest_timestamp = latest_timestamp

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.API} Fetched {len(all_entities)} total entities from API. "
                f"Latest timestamp: {latest_timestamp}"
            )

            return all_entities

        except Exception as e:
            raise APIError(f"Failed to process gzipped response: {e}") from e

    def apply_incremental_filtering(
        self, entities: List[C2], since_timestamp: Optional[str]
    ) -> List[C2]:
        """Apply client-side incremental filtering."""
        if not since_timestamp:
            return self._apply_first_run_limits(entities)

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.DEBUG} Starting client-side filtering with since_timestamp: {since_timestamp}"
        )

        filtered_entities = []
        for entity in entities:
            entity_timestamp = entity.get("timestamp")
            if entity_timestamp and entity_timestamp > since_timestamp:
                filtered_entities.append(entity)

        self.helper.connector_logger.error(
            f"{LoggingPrefixes.CLIENT_FILTER} *** CRITICAL *** Filtered {len(entities)} entities "
            f"to {len(filtered_entities)} newer than {since_timestamp}"
        )

        # Debug: Log some sample timestamps for troubleshooting
        if len(entities) > 0:
            sample_timestamps = [
                entities[i].get("timestamp") for i in range(min(5, len(entities)))
            ]
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.DEBUG} Sample entity timestamps: {sample_timestamps}, "
                f"since_timestamp: {since_timestamp}"
            )

        return filtered_entities

    def _apply_first_run_limits(self, entities: List[C2]) -> List[C2]:
        """Apply limits for first run to prevent queue explosion."""
        if len(entities) > ProcessingLimits.MAX_FIRST_RUN:
            limited_entities = entities[: ProcessingLimits.MAX_FIRST_RUN]
            self.helper.connector_logger.warning(
                f"{LoggingPrefixes.FIRST_RUN_LIMIT} *** LIMITED *** Processing only "
                f"{ProcessingLimits.MAX_FIRST_RUN} of {len(entities)} entities "
                f"to prevent queue explosion"
            )
            return limited_entities

        return entities

    def apply_emergency_limits(self, entities: List[C2]) -> List[C2]:
        """Apply emergency hard limits."""
        original_count = len(entities)
        if original_count > ProcessingLimits.EMERGENCY_MAX_ENTITIES:
            limited_entities = entities[: ProcessingLimits.EMERGENCY_MAX_ENTITIES]
            self.helper.connector_logger.error(
                f"{LoggingPrefixes.EMERGENCY_LIMIT} *** HARD LIMIT *** Processing only "
                f"{ProcessingLimits.EMERGENCY_MAX_ENTITIES} entities to prevent queue explosion. "
                f"Original count: {original_count}"
            )
            return limited_entities

        return entities


class ConnectorClient:
    """
    A client for interacting with the Hunt.IO API.

    This class handles making HTTP requests to the API, including authentication,
    error handling, and response processing with improved separation of concerns.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config: "ConfigLoader"):
        """Initialize the ConnectorClient with necessary configurations."""
        self.helper = helper
        self.config = config

        self.session_manager = HTTPSessionManager(helper)
        self.data_processor = DataProcessor(helper)

        # Create HTTP session with resilience features
        self.session = self.session_manager.create_session(
            self.config.hunt_io.api_key.get_secret_value()
        )

    @property
    def latest_timestamp(self) -> Optional[str]:
        """Get the latest timestamp from the data processor."""
        return self.data_processor.latest_timestamp

    def _request_data(
        self, api_url: str, params: Optional[dict] = None
    ) -> requests.Response:
        """
        Sends a GET request to the specified API URL with enhanced error handling and timeouts.

        Args:
            api_url: The URL to send the request to.
            params: Query parameters for the request.

        Returns:
            The HTTP response object.

        Raises:
            APIError: If an API-related error occurs.
            RetryableError: If a retryable error occurs.
            NonRetryableError: If a non-retryable error occurs.
        """
        start_time = time.time()

        try:
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.API} HTTP GET Request to endpoint",
                {"url_path": api_url},
            )

            # Make request with configured timeouts
            response = self.session.get(
                api_url,
                params=params,
                timeout=(APIConstants.CONNECT_TIMEOUT, APIConstants.READ_TIMEOUT),
            )

            elapsed_time = time.time() - start_time
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.HTTP_RESILIENCE} Request completed in {elapsed_time:.2f}s"
            )

            response.raise_for_status()
            return response

        except ConnectTimeout as timeout_err:
            elapsed_time = time.time() - start_time
            error_msg = (
                f"Connection timeout after {elapsed_time:.2f}s "
                f"(limit: {APIConstants.CONNECT_TIMEOUT}s)"
            )
            self.helper.connector_logger.error(
                f"{LoggingPrefixes.HTTP_RESILIENCE} {error_msg}",
                {"url_path": api_url, "error": str(timeout_err)},
            )
            self._refresh_session_on_timeout()
            raise RetryableError(error_msg) from timeout_err

        except ReadTimeout as timeout_err:
            elapsed_time = time.time() - start_time
            error_msg = f"Read timeout after {elapsed_time:.2f}s (limit: {APIConstants.READ_TIMEOUT}s)"
            self.helper.connector_logger.error(
                f"{LoggingPrefixes.HTTP_RESILIENCE} {error_msg}",
                {"url_path": api_url, "error": str(timeout_err)},
            )
            self._refresh_session_on_timeout()
            raise RetryableError(error_msg) from timeout_err

        except HTTPError as http_err:
            elapsed_time = time.time() - start_time
            status_code = (
                http_err.response.status_code if http_err.response else "unknown"
            )
            error_msg = f"HTTP {status_code} error after {elapsed_time:.2f}s"

            self.helper.connector_logger.error(
                f"{LoggingPrefixes.HTTP_RESILIENCE} {error_msg}",
                {"url_path": api_url, "error": str(http_err)},
            )

            # Determine if error is retryable
            if status_code in APIConstants.RETRY_STATUS_CODES:
                self.helper.connector_logger.warning(
                    f"{LoggingPrefixes.HTTP_RESILIENCE} Service temporarily unavailable "
                    f"(HTTP {status_code}), retries will be handled by urllib3"
                )
                raise RetryableError(error_msg, status_code) from http_err
            else:
                raise APIError(error_msg, status_code) from http_err

        except RequestException as req_err:
            elapsed_time = time.time() - start_time
            error_msg = f"Request error after {elapsed_time:.2f}s"

            self.helper.connector_logger.error(
                f"{LoggingPrefixes.HTTP_RESILIENCE} {error_msg}",
                {"url_path": api_url, "error": str(req_err)},
            )
            self._refresh_session_on_timeout()
            raise RetryableError(error_msg) from req_err

        except Exception as err:
            elapsed_time = time.time() - start_time
            error_msg = f"Unexpected error after {elapsed_time:.2f}s: {err}"

            self.helper.connector_logger.error(
                f"{LoggingPrefixes.HTTP_RESILIENCE} {error_msg}",
                {"url_path": api_url, "error": str(err)},
            )
            raise APIError(error_msg) from err

    def _refresh_session_on_timeout(self) -> None:
        """Refresh the session when timeouts occur to recover from stale connections."""
        try:
            self.helper.connector_logger.info(
                f"{LoggingPrefixes.HTTP_RESILIENCE} Refreshing HTTP session due to connection issues"
            )

            # Close existing session
            self.session.close()

            # Create new session with same configuration
            self.session = self.session_manager.create_session(
                self.config.hunt_io.api_key.get_secret_value()
            )

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.HTTP_RESILIENCE} HTTP session refreshed successfully"
            )

        except Exception as e:
            self.helper.connector_logger.error(
                f"{LoggingPrefixes.HTTP_RESILIENCE} Error refreshing session: {e}"
            )

    def get_entities(
        self, since_timestamp: Optional[str] = None, params: Optional[dict] = None
    ) -> Optional[List[C2]]:
        """
        Fetches and processes entities from the API with incremental support.

        Args:
            since_timestamp: ISO timestamp to fetch only newer entities.
            params: Additional query parameters for the API request.

        Returns:
            A list of entities if successful, or None if an error occurs.
        """
        try:
            # Note: Hunt API may not support 'since' parameter, so we'll do client-side filtering
            request_params = params or {}

            if since_timestamp:
                self.helper.connector_logger.info(
                    f"{LoggingPrefixes.API} Fetching ALL entities, will filter client-side "
                    f"for records since: {since_timestamp}"
                )
            else:
                self.helper.connector_logger.info(
                    f"{LoggingPrefixes.API} Fetching ALL entities (first run or full refresh)"
                )

            # Make API request
            response = self._request_data(
                str(self.config.hunt_io.api_base_url), params=request_params
            )

            # Process response data
            all_entities = self.data_processor.process_gzipped_response(response)

            # Apply incremental filtering
            filtered_entities = self.data_processor.apply_incremental_filtering(
                all_entities, since_timestamp
            )

            # Apply emergency limits
            final_entities = self.data_processor.apply_emergency_limits(
                filtered_entities
            )

            return final_entities

        except (APIError, RetryableError, NonRetryableError) as api_err:
            self.helper.connector_logger.error(
                f"API error while retrieving entities: {api_err}"
            )
        except Exception as err:
            self.helper.connector_logger.error(
                f"Unexpected error while retrieving entities: {err}"
            )

        return None
