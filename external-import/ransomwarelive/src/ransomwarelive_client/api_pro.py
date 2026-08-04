from connectors_sdk import (
    ApiClientError,
    ApiRateLimitError,
    ApiServerError,
    BaseClientApi,
)
from pycti import OpenCTIConnectorHelper
from ransomwarelive_client.exceptions import RansomwareAPIError
from ransomwarelive_client.protocol import (
    MAX_RETRIES,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_BACKOFF_FACTOR,
)


class RansomwareAPIProClient(BaseClientApi):
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str,
    ) -> None:
        # Logging (backward compatible with V2 client)
        self._logger = helper.connector_logger

        # For later headers building
        self._api_key = api_key

        # Init client with same retry strategy as V2 client (backward compatible)
        super().__init__(
            base_url=base_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            max_retries=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF_FACTOR,
        )

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "User-Agent": "OpenCTI",
            "X-API-KEY": self._api_key,
        }

    @staticmethod
    def _ensure_feed_list(data: dict, path: str) -> list[dict]:
        if data is None:
            return []

        results_key = path.split("/")[1]  # e.g., "groups" or "victims"
        results = data.get(results_key) or []
        if not isinstance(results, list):
            raise RansomwareAPIError(
                "Unexpected Ransomware API response type for feed",
                {"url": f"GET {path}", "response_type": type(results).__name__},
            )
        if not all(isinstance(item, dict) for item in results):
            raise RansomwareAPIError(
                "Unexpected Ransomware API feed item type",
                {"url": f"GET {path}", "response_type": "list"},
            )

        return results

    def _get_feed(self, path: str, params: dict | None = None) -> list[dict]:
        try:
            data = self._get(path, params=params)
            return self._ensure_feed_list(data, path)
        except ApiRateLimitError as err:
            error_message = (
                "Exceeded maximum retries for Ransomware API due to rate limiting"
            )
            error_metadata = {"url": f"GET {path}", "status_code": err.status_code}

            self._logger.error(error_message, error_metadata)
            raise RansomwareAPIError(error_message, error_metadata) from err
        except (ApiClientError, ApiServerError) as err:
            error_message = "Error while fetching Ransomware API"
            error_metadata = {
                "url": f"GET {path}",
                "status_code": err.status_code,
                "response_body": err.response_body,
            }

            self._logger.error(error_message, error_metadata)
            raise RansomwareAPIError(error_message, error_metadata) from err

    def get_groups(self) -> list[dict]:
        return self._get_feed("/groups")

    def get_recent_victims(self) -> list[dict]:
        return self._get_feed("/victims/recent")

    def get_victims(self, year: int, month: int) -> list[dict]:
        return self._get_feed("/victims", {"year": year, "month": month})
