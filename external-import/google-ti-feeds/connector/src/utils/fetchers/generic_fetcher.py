"""Generic API fetcher for any endpoint with configurable response handling.

This module provides a flexible fetcher that can work with any API endpoint,
handle both model-based and raw responses, and provide consistent error handling.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.exceptions.api_network_error import ApiNetworkError
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

LOG_PREFIX = "[GenericFetcher]"


class GenericFetcher:
    """Generic fetcher for any API endpoint with flexible response handling."""

    def __init__(
        self,
        config: GenericFetcherConfig,
        api_client: ApiClient,
        base_headers: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the generic fetcher.

        Args:
            config: Configuration specifying endpoint, models, exceptions, etc.
            api_client: Client for making API requests
            base_headers: Base headers to include in all requests
            base_url: Base URL to prepend to all endpoint paths
            logger: Logger for logging messages

        """
        self.config = config
        self.api_client = api_client
        self.base_url = base_url
        self.logger = logger or logging.getLogger(__name__)

        self.headers = {}
        if base_headers:
            self.headers.update(base_headers)
        if config.headers:
            self.headers.update(config.headers)

    async def fetch_single(self, **endpoint_params: Any) -> Optional[Any]:
        """Fetch a single entity from the configured endpoint.

        Args:
            **endpoint_params: Parameters to substitute in the endpoint URL and query parameters

        Returns:
            Entity data (model instance or raw data) or None if not found

        Raises:
            Configured exception class: If there's an error fetching the entity

        """
        entity_id = (
            endpoint_params.get("id") or endpoint_params.get("entity_id") or None
        )

        self._log_fetch_start(self.config.display_name_singular, entity_id)

        response = await self._make_api_call(endpoint_params, entity_id)

        if response is not None:
            self.logger.debug(
                f"{LOG_PREFIX} Successfully fetched {self.config.entity_type} data for {entity_id}"
            )
            return response
        else:
            self.logger.debug(
                f"{LOG_PREFIX} No data returned for {self.config.display_name_singular} {entity_id}"
            )
            return None

    async def fetch_multiple(
        self, entity_ids: List[str], **endpoint_params: Any
    ) -> List[Any]:
        """Fetch multiple entities by their IDs.

        Args:
            entity_ids: List of entity IDs to fetch
            **endpoint_params: Additional parameters for endpoint formatting and query parameters

        Returns:
            List of entity objects (successful fetches only)

        Raises:
            Configured exception class: If there's a critical error

        """
        entities: List[Any] = []

        self._log_fetch_start(
            self.config.display_name, "multiple", count=len(entity_ids)
        )

        self.logger.debug(
            f"{LOG_PREFIX} Starting sequential API requests for {len(entity_ids)} {self.config.entity_type} entities"
        )

        for idx, entity_id in enumerate(entity_ids):
            try:
                params = {**endpoint_params, "id": entity_id, "entity_id": entity_id}
                result = await self.fetch_single(**params)

                if result is not None:
                    self.logger.debug(
                        f"{LOG_PREFIX} Successfully fetched {self.config.entity_type} #{idx + 1}/{len(entity_ids)}: {entity_id}"
                    )
                    entities.append(result)
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} No data returned for {self.config.display_name_singular} {entity_id}"
                    )
            except Exception as e:
                self.logger.warning(
                    f"{LOG_PREFIX} Failed to fetch {self.config.display_name_singular} {entity_id}: {str(e)}"
                )
                continue

        self._log_fetch_result(self.config.display_name, len(entities))
        return entities

    async def fetch_list(self, **endpoint_params: Any) -> List[Any]:
        """Fetch a list of entities from the endpoint.

        Args:
            **endpoint_params: Parameters to substitute in the endpoint URL and query parameters

        Returns:
            List of entities

        Raises:
            Configured exception class: If there's an error fetching the list

        """
        self._log_fetch_start(self.config.display_name, "list")

        response = await self._make_api_call(endpoint_params)

        if response is not None:
            entities = response if isinstance(response, list) else [response]
            self._log_fetch_result(self.config.display_name, len(entities))
            return entities
        else:
            self.logger.debug(
                f"{LOG_PREFIX} No data returned for {self.config.display_name}"
            )
            return []

    async def fetch_full_response(self, **endpoint_params: Any) -> Optional[Any]:
        """Fetch the complete response model from the endpoint.

        This method returns the full response model (with proper deserialization),
        which is useful when you need the complete response structure (e.g., for pagination metadata).

        Args:
            **endpoint_params: Parameters to substitute in the endpoint URL and query parameters

        Returns:
            Complete response model or None if no data

        Raises:
            Configured exception class: If there's an error fetching the response

        """
        self._log_fetch_start(self.config.display_name, "full_response")

        response = await self._make_api_call(endpoint_params)

        if response is not None:
            data_count = 1
            if isinstance(response, list):
                data_count = len(response)
            elif isinstance(response, dict):
                for key in ["data", "items", "results", "records"]:
                    if key in response and isinstance(response[key], list):
                        data_count = len(response[key])
                        break
            elif hasattr(response, "data") and isinstance(response.data, list):
                data_count = len(response.data)
            elif hasattr(response, "items") and isinstance(response.items, list):
                data_count = len(response.items)
            elif hasattr(response, "results") and isinstance(response.results, list):
                data_count = len(response.results)
            elif hasattr(response, "records") and isinstance(response.records, list):
                data_count = len(response.records)

            self._log_fetch_result(self.config.display_name, data_count)
            return response
        else:
            self.logger.debug(
                f"{LOG_PREFIX} No data returned for {self.config.display_name}"
            )
            return None

    def _handle_api_error(
        self, net_err: ApiNetworkError, endpoint: str, entity_id: Optional[str] = None
    ) -> None:
        """Handle API network errors.

        Args:
            net_err: The network error
            endpoint: The endpoint that failed
            entity_id: Optional entity ID for context

        Raises:
            Configured exception class: Rethrows the error with additional context

        """
        if entity_id:
            error_msg = f"Network error fetching {self.config.display_name_singular} {entity_id}: {str(net_err)}"
            self.logger.warning(
                f"{LOG_PREFIX} Network error at {endpoint} for {self.config.entity_type} {entity_id}: {str(net_err)}"
            )
        else:
            error_msg = (
                f"Network error fetching {self.config.display_name}: {str(net_err)}"
            )
            self.logger.warning(
                f"{LOG_PREFIX} Network error at {endpoint} for {self.config.entity_type}: {str(net_err)}"
            )

        exception = self.config.create_exception(error_msg, endpoint=endpoint)
        raise exception from net_err

    def _handle_general_error(
        self, e: Exception, endpoint: str, entity_id: Optional[str] = None
    ) -> None:
        """Handle general exceptions.

        Args:
            e: The exception
            endpoint: The endpoint that failed
            entity_id: Optional entity ID for context

        Raises:
            Configured exception class: Rethrows the error with additional context

        """
        if entity_id:
            error_msg = f"Error fetching {self.config.display_name_singular} {entity_id}: {str(e)}"
            self.logger.error(
                f"{LOG_PREFIX} Failed to fetch {self.config.entity_type} {entity_id} from {endpoint}: {str(e)}"
            )
        else:
            error_msg = f"Error fetching {self.config.display_name}: {str(e)}"
            self.logger.error(
                f"{LOG_PREFIX} Failed to fetch {self.config.entity_type} from {endpoint}: {str(e)}"
            )

        exception = self.config.create_exception(error_msg, endpoint=endpoint)
        raise exception from e

    def _log_fetch_start(
        self,
        entity_type: Optional[str],
        entity_id: Optional[str],
        count: Optional[int] = None,
    ) -> None:
        """Log the start of a fetch operation.

        Args:
            entity_type: Type of entity being fetched
            entity_id: ID of the specific entity
            count: Number of entities being fetched (optional)

        """
        if entity_id:
            self.logger.debug(f"{LOG_PREFIX} Fetching {entity_type} {entity_id}...")
        elif count:
            self.logger.debug(f"{LOG_PREFIX} Fetching {count} {entity_type}...")
        else:
            self.logger.debug(f"{LOG_PREFIX} Fetching {entity_type}...")

    async def _make_api_call(
        self,
        endpoint_params: Dict[str, Any],
        entity_id: Optional[str] = None,
        use_raw_response: bool = False,
    ) -> Optional[Any]:
        """Make the actual API call with error handling.

        Args:
            endpoint_params: Parameters for endpoint formatting and query parameters
            entity_id: Optional entity ID for context in errors
            use_raw_response: If True, return the raw response without model processing

        Returns:
            Processed API response (via response_key) or raw response if use_raw_response=True

        Raises:
            Configured exception class: If there's an error making the API call

        """
        query_params = endpoint_params

        try:
            endpoint = self.config.format_endpoint(**query_params)
            if self.base_url:
                if endpoint.startswith("/") and self.base_url.endswith("/"):
                    full_endpoint = f"{self.base_url[:-1]}{endpoint}"
                elif not endpoint.startswith("/") and not self.base_url.endswith("/"):
                    full_endpoint = f"{self.base_url}/{endpoint}"
                else:
                    full_endpoint = f"{self.base_url}{endpoint}"
                endpoint = full_endpoint

        except ValueError as e:
            error_msg = f"{LOG_PREFIX} Invalid endpoint parameters for {self.config.display_name}: {str(e)}"
            self.logger.error(error_msg)
            raise self.config.create_exception(error_msg) from e

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching {self.config.entity_type} from {endpoint} with query params: {query_params}"
            )

            response = await self.api_client.call_api(
                url=endpoint,
                method=self.config.method,
                headers=self.headers,
                params=query_params if query_params else None,
                model=self.config.response_model if not use_raw_response else None,
                response_key=self.config.response_key if not use_raw_response else None,
                timeout=self.config.timeout,
            )

            if self.config.save_to_file:
                await self._save_response_to_file(response, endpoint, query_params)

            return response

        except ApiNetworkError as net_err:
            self._handle_api_error(net_err, endpoint, entity_id)
            return None
        except Exception as e:
            self._handle_general_error(e, endpoint, entity_id)
            return None

    async def _save_response_to_file(
        self,
        response: Any,
        endpoint: str,
        query_params: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Save the raw response to a file for debugging/testing purposes.

        Args:
            response: The raw response data
            endpoint: The endpoint that was called
            query_params: Query parameters used in the request

        """
        try:
            request_info = {
                "endpoint": endpoint,
                "query_params": query_params or {},
                "entity_type": self.config.entity_type,
                "method": self.config.method,
            }

            if hasattr(response, "model_dump"):
                response_data = response.model_dump()
            elif hasattr(response, "dict"):
                response_data = response.dict()
            elif hasattr(response, "__dict__"):
                response_data = response.__dict__
            else:
                response_data = response

            file_content = {"request_info": request_info, "response": response_data}

            content_str = json.dumps(file_content, sort_keys=True, default=str)
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()

            debug_dir = Path("debug_responses")
            debug_dir.mkdir(exist_ok=True)

            filename = f"{self.config.entity_type}_{content_hash[:16]}.json"
            file_path = debug_dir / filename

            if not file_path.exists():
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(file_content, f, indent=2, default=str)

                self.logger.debug(
                    f"{LOG_PREFIX} Saved response debug file: {file_path} for {self.config.entity_type} from {endpoint}"
                )
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} Debug file already exists: {file_path} for {self.config.entity_type}"
                )

        except Exception as e:
            self.logger.warning(
                f"{LOG_PREFIX} Failed to save debug response file: {str(e)}"
            )

    def _log_fetch_result(self, entity_type: Optional[str], count: int = 1) -> None:
        """Log the result of a fetch operation.

        Args:
            entity_type: Type of entity that was fetched
            count: Number of entities fetched

        """
        if count > 0:
            self.logger.info(f"{LOG_PREFIX} Fetched {count} {entity_type}")
        else:
            self.logger.debug(f"{LOG_PREFIX} No {entity_type} found")
