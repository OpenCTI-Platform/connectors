from dataclasses import dataclass

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl
from tenacity import (
    Retrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)
from tenacity.wait import wait_base


@dataclass(frozen=True)
class HttpRetrySettings:
    """HTTP retry/backoff configuration for API requests."""

    max_attempts: int = 3
    initial_seconds: float = 1
    max_seconds: float = 60


@dataclass(frozen=True)
class RecordedFutureAsiClientConfig:
    """Connection settings for the Recorded Future ASI API client."""

    base_url: HttpUrl
    api_key: str
    api_v1_base_url: HttpUrl = "https://api.securitytrails.com/v1"
    retry: HttpRetrySettings | None = None


def _retry_after_or_exponential_wait(
    exponential_wait: wait_base,
    max_seconds: float,
):
    """Return a tenacity wait callable honoring Retry-After on 429 responses."""

    def wait(retry_state) -> float:
        exc = retry_state.outcome.exception()
        if isinstance(exc, requests.HTTPError) and exc.response is not None:
            if exc.response.status_code == 429:
                retry_after = exc.response.headers.get("Retry-After")
                if retry_after is not None:
                    try:
                        return min(int(retry_after), max_seconds)
                    except (ValueError, TypeError):
                        pass
        return exponential_wait(retry_state)

    return wait


class RecordedFutureAsiClient:
    _RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: RecordedFutureAsiClientConfig,
    ):
        """
        Initialize the client with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            config (RecordedFutureAsiClientConfig): API connection and retry settings.
        """
        retry_settings = config.retry or HttpRetrySettings()
        self.helper = helper
        self.base_url = str(config.base_url).rstrip("/")
        self.api_v1_base_url = str(config.api_v1_base_url).rstrip("/")
        self.retry_max_attempts = retry_settings.max_attempts
        self.retry_initial_seconds = retry_settings.initial_seconds
        self.retry_max_seconds = retry_settings.max_seconds
        headers = {
            "accept": "application/json",
            "apikey": config.api_key,
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

    @classmethod
    def _is_retryable(cls, exc: BaseException) -> bool:
        if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
            return True
        if isinstance(exc, requests.HTTPError):
            if exc.response is None:
                return False
            return exc.response.status_code in cls._RETRYABLE_STATUS_CODES
        return False

    def _request_once(
        self, api_url: str, params: dict | None = None
    ) -> requests.Response:
        response = self.session.get(api_url, params=params, timeout=30)
        response.raise_for_status()
        return response

    def _request_data(
        self, api_url: str, params: dict | None = None
    ) -> requests.Response:
        """
        Internal method to handle API GET requests.

        :param api_url: Full URL for the API endpoint.
        :param params: Optional query parameters.
        :return: HTTP response on success.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        self.helper.connector_logger.info(
            "[API] HTTP Get Request to endpoint", {"url_path": api_url}
        )

        def _log_before_sleep(retry_state) -> None:
            exc = retry_state.outcome.exception()
            status_code = None
            if isinstance(exc, requests.HTTPError) and exc.response is not None:
                status_code = exc.response.status_code
            wait_seconds = (
                retry_state.next_action.sleep if retry_state.next_action else 0
            )
            self.helper.connector_logger.warning(
                "[API] Retrying HTTP request after failure",
                {
                    "status_code": status_code,
                    "attempt": retry_state.attempt_number,
                    "max_attempts": self.retry_max_attempts,
                    "wait_seconds": wait_seconds,
                    "url_path": api_url,
                },
            )

        retryer = Retrying(
            retry=retry_if_exception(self._is_retryable),
            stop=stop_after_attempt(self.retry_max_attempts),
            wait=_retry_after_or_exponential_wait(
                wait_exponential_jitter(
                    initial=self.retry_initial_seconds,
                    max=self.retry_max_seconds,
                    jitter=1,
                ),
                self.retry_max_seconds,
            ),
            before_sleep=_log_before_sleep,
            reraise=True,
        )
        return retryer(self._request_once, api_url, params)

    @staticmethod
    def _parse_list_response(payload: dict) -> tuple[list[dict], str | None]:
        """
        Extract exposure items and the next pagination cursor from a list response.

        :param payload: JSON body from the exposures list endpoint.
        :return: Tuple of exposure summary items and optional next cursor.
        """
        data = payload.get("data") or []
        if not isinstance(data, list):
            data = []
        pagination = (payload.get("meta") or {}).get("pagination") or {}
        next_cursor = pagination.get("next_cursor")
        return data, next_cursor

    @staticmethod
    def _parse_assets_response(payload: dict) -> tuple[dict, list[dict], str | None]:
        """
        Extract signature, asset exposures, and next cursor from a get-assets response.

        :param payload: JSON body from the exposure assets endpoint.
        :return: Tuple of signature dict, asset exposure items, and optional next cursor.
        """
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        signature = data.get("signature") or {}
        asset_exposures = data.get("asset_exposures") or []
        pagination = (payload.get("meta") or {}).get("pagination") or {}
        next_cursor = pagination.get("next_cursor")
        return signature, asset_exposures, next_cursor

    @staticmethod
    def _parse_history_response(payload: dict) -> tuple[list[dict], list[dict]]:
        """
        Extract added and removed rules from a history activity response.

        Iterates all snapshots in ``data[]`` and deduplicates by rule ``id`` within
        each list (last wins) to handle overlapping snapshot windows.

        :param payload: JSON body from the exposure history activity endpoint.
        :return: Tuple of added rule dicts and removed rule dicts.
        """
        added_by_id: dict[str, dict] = {}
        removed_by_id: dict[str, dict] = {}

        for snapshot in payload.get("data") or []:
            if not isinstance(snapshot, dict):
                continue
            for rule in snapshot.get("added_rules") or []:
                if isinstance(rule, dict):
                    rule_id = rule.get("id")
                    if rule_id:
                        added_by_id[rule_id] = rule
            for rule in snapshot.get("removed_rules") or []:
                if isinstance(rule, dict):
                    rule_id = rule.get("id")
                    if rule_id:
                        removed_by_id[rule_id] = rule

        return list(added_by_id.values()), list(removed_by_id.values())

    def get_exposure_history(
        self,
        project_id: str,
        *,
        start: int | None = None,
    ) -> tuple[list[dict], list[dict]]:
        """
        Fetch exposure rule changes from the v1 history activity endpoint.

        :param project_id: ASI project identifier.
        :param start: Optional Unix timestamp (seconds) for incremental sync.
        :return: Tuple of added rule dicts and removed rule dicts.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        url = f"{self.api_v1_base_url}/asi/rules/history/{project_id}/activity"
        params: dict | None = None
        if start is not None:
            params = {"start": start}

        response = self._request_data(url, params=params)
        return self._parse_history_response(response.json())

    def list_exposures_page(
        self,
        project_id: str,
        limit: int = 100,
        cursor: str | None = None,
        **filters,
    ) -> tuple[list[dict], str | None]:
        """
        Fetch one page of exposures for a project.

        :param project_id: ASI project identifier.
        :param limit: Number of exposures to fetch per page (1-1000).
        :param cursor: Optional pagination cursor.
        :param filters: Optional API query filters (e.g. filter_severity_min).
        :return: Tuple of exposure summary items and optional next cursor.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        url = f"{self.base_url}/projects/{project_id}/exposures"
        params: dict = {"limit": limit, **filters}
        if cursor:
            params["cursor"] = cursor

        response = self._request_data(url, params=params)
        return self._parse_list_response(response.json())

    def list_exposures(
        self,
        project_id: str,
        limit: int = 100,
        cursor: str | None = None,
        **filters,
    ) -> list[dict]:
        """
        List all exposures for a project, following cursor-based pagination.

        :param project_id: ASI project identifier.
        :param limit: Number of exposures to fetch per page (1-1000).
        :param cursor: Optional starting pagination cursor.
        :param filters: Optional API query filters (e.g. filter_severity_min).
        :return: All exposure summary dicts from the API (signature + asset_count).
        :raises requests.RequestException: If the first page request fails.
        """
        exposures: list[dict] = []
        next_cursor = cursor
        url = f"{self.base_url}/projects/{project_id}/exposures"

        while True:
            try:
                page_items, next_cursor = self.list_exposures_page(
                    project_id,
                    limit=limit,
                    cursor=next_cursor,
                    **filters,
                )
                exposures.extend(page_items)
            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "[API] Error while fetching exposures",
                    {"url_path": url, "error": str(err)},
                )
                raise

            if not next_cursor:
                break

        return exposures

    def list_exposures_batch(
        self,
        project_id: str,
        *,
        page_limit: int,
        run_limit: int,
        cursor: str | None = None,
        **filters,
    ) -> tuple[list[dict], str | None]:
        """
        Fetch up to ``run_limit`` exposures, following cursor-based pagination.

        :param project_id: ASI project identifier.
        :param page_limit: Number of exposures to fetch per API page.
        :param run_limit: Maximum exposures to collect in this batch.
        :param cursor: Optional starting pagination cursor.
        :param filters: Optional API query filters (e.g. filter_severity_min).
        :return: Tuple of exposure summary items and optional next cursor for resuming.
        :raises requests.RequestException: If the first page request fails.
        """
        exposures: list[dict] = []
        next_cursor = cursor
        url = f"{self.base_url}/projects/{project_id}/exposures"

        while len(exposures) < run_limit:
            remaining = run_limit - len(exposures)
            try:
                page_items, next_cursor = self.list_exposures_page(
                    project_id,
                    limit=min(page_limit, remaining),
                    cursor=next_cursor,
                    **filters,
                )
                exposures.extend(page_items)
            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "[API] Error while fetching exposures",
                    {"url_path": url, "error": str(err)},
                )
                if exposures:
                    self.helper.connector_logger.warning(
                        "[API] Returning partial exposure results after pagination failure",
                        {"collected_count": len(exposures)},
                    )
                    if len(exposures) > run_limit:
                        exposures = exposures[:run_limit]
                    return exposures, next_cursor
                raise

            if len(exposures) >= run_limit:
                break
            if not next_cursor:
                break

        if len(exposures) > run_limit:
            exposures = exposures[:run_limit]

        return exposures, next_cursor

    def get_exposure_assets_page(
        self,
        project_id: str,
        signature_id: str,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[dict, list[dict], str | None]:
        """
        Fetch one page of assets for an exposure signature.

        :param project_id: ASI project identifier.
        :param signature_id: Exposure signature identifier.
        :param limit: Number of assets to fetch per page (1-1000).
        :param cursor: Optional pagination cursor.
        :return: Tuple of signature dict, asset exposure items, and optional next cursor.
        :raises requests.RequestException: On non-2xx responses or transport errors.
        """
        url = f"{self.base_url}/projects/{project_id}/exposures/{signature_id}"
        params: dict = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        response = self._request_data(url, params=params)
        return self._parse_assets_response(response.json())

    def get_exposure_assets(
        self,
        project_id: str,
        signature_id: str,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict:
        """
        Fetch all assets for an exposure signature, following cursor-based pagination.

        :param project_id: ASI project identifier.
        :param signature_id: Exposure signature identifier.
        :param limit: Number of assets to fetch per page (1-1000).
        :param cursor: Optional starting pagination cursor.
        :return: Dict with ``signature`` and accumulated ``asset_exposures`` items.
        :raises requests.RequestException: If the first page request fails.
        """
        signature: dict = {}
        asset_exposures: list[dict] = []
        next_cursor = cursor
        url = f"{self.base_url}/projects/{project_id}/exposures/{signature_id}"

        while True:
            try:
                page_signature, page_assets, next_cursor = (
                    self.get_exposure_assets_page(
                        project_id,
                        signature_id,
                        limit=limit,
                        cursor=next_cursor,
                    )
                )
                if page_signature:
                    signature = page_signature
                asset_exposures.extend(page_assets)
            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "[API] Error while fetching exposure assets",
                    {
                        "url_path": url,
                        "signature_id": signature_id,
                        "error": str(err),
                    },
                )
                raise

            if not next_cursor:
                break

        return {"signature": signature, "asset_exposures": asset_exposures}
