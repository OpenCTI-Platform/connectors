"""Deployment write-back of the Splunk connector: KV store read-back and hits."""

from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import requests
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentVendorAdapter,
    HitCollection,
    IndicatorDeployment,
    VendorHit,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import (
    deployment_failure_reason,
    parse_datetime,
)

if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper
    from settings import ConnectorSettings
    from splunk import KVStore

HITS_MAX_RESULTS = 10000
"""Maximum number of saved search results read per hit collection."""

MAX_ERROR_DETAIL_LENGTH = 500
"""Maximum length of the Splunk response appended to a logged error."""

PLATFORM_NAME = "Splunk"
"""Name of the security platform in the deployment failure reasons."""

WRITE_ACTION = "KV Store write"
"""What Splunk is asked to do when an indicator is pushed."""


class SplunkDeploymentError(Exception):
    """A KV store write Splunk refused, with the reason OpenCTI shows."""


def describe_error(error: BaseException) -> str:
    """Describe a Splunk API error for the logs.

    Args:
        error: The error raised by a KV store call.

    Returns:
        The error, followed by the Splunk response body for HTTP errors (it
        carries the reason of the rejection).
    """
    message = str(error) or type(error).__name__
    response = getattr(error, "response", None)
    detail = getattr(response, "text", None) if response is not None else None
    if isinstance(detail, str) and detail.strip():
        message = f"{message} - {detail.strip()[:MAX_ERROR_DETAIL_LENGTH]}"
    return message


def failure_reason(error: BaseException) -> str:
    """Return the reason OpenCTI shows for an indicator the KV store did not take.

    Args:
        error: The error raised by the KV store write.

    Returns:
        One short sentence naming Splunk and the cause; the Splunk response is left
        to the logs (`describe_error`).
    """
    if isinstance(error, requests.HTTPError):
        status_code = getattr(error.response, "status_code", None)
        return deployment_failure_reason(
            PLATFORM_NAME,
            WRITE_ACTION,
            status_code if isinstance(status_code, int) else HTTPStatus.OK,
        )
    if isinstance(error, requests.RequestException):
        return deployment_failure_reason(PLATFORM_NAME, WRITE_ACTION)
    return str(error) or type(error).__name__


def _first(value: Any) -> Any:
    """Return the first value of a Splunk multivalue field."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _text(value: Any) -> str | None:
    """Return a non-empty string of a (multivalue) field, if any."""
    value = _first(value)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _count(value: Any) -> int:
    """Return the hit count of a result row (1 when absent or invalid).

    The count stands for the matches at the `_time` of the row: successive reads
    overlap and a row at or before the last hit reported is skipped as a whole, so
    a row counting matches of several times would lose the newer ones.
    """
    try:
        count = int(float(_first(value)))
    except (TypeError, ValueError, OverflowError):
        return 1
    return max(count, 1)


def parse_splunk_time(value: Any) -> datetime | None:
    """Parse a Splunk time value.

    Args:
        value: Epoch seconds (number or string) or an ISO 8601 string.

    Returns:
        A timezone-aware datetime, or `None` when the value cannot be parsed.
    """
    value = _first(value)
    if value is None or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return parse_datetime(value) if isinstance(value, str) else None


class SplunkKVStoreDeploymentAdapter(DeploymentVendorAdapter):
    """Vendor operations of the deployment reconciliation for the Splunk KV store.

    - Read-back: the indicator items of the collection (`type` = `indicator`). The
      KV store key of an item is the OpenCTI id of the indicator.
    - Removal: the item is deleted from the collection.
    - Re-push: the stream create path (payload enrichment, then KV store insert).
    - Hits: Splunk does not match the KV store content by itself. Matches are read
      from an optional saved search (`SPLUNK_HITS_SAVED_SEARCH`), run over the time
      range of the hit collection; each result carries `opencti_id` (the KV store
      key) or `value` (the matched observable value), `_time` and optionally `count`.
    """

    def __init__(
        self,
        kvstore: "KVStore",
        *,
        push_indicator: Callable[[dict[str, Any]], str | None],
        hits_saved_search: str | None = None,
        hits_max_results: int = HITS_MAX_RESULTS,
    ) -> None:
        """Initialize the adapter.

        Args:
            kvstore: The KV store client of the connector.
            push_indicator: The stream create path of the connector.
            hits_saved_search: The saved search returning the matches, if any.
            hits_max_results: Maximum number of saved search results per collection.
        """
        self._kvstore = kvstore
        self._push_indicator = push_indicator
        self._hits_saved_search = (hits_saved_search or "").strip() or None
        self._hits_max_results = hits_max_results

    @property
    def hits_supported(self) -> bool:
        """Tell whether a saved search is configured to read the hits."""
        return self._hits_saved_search is not None

    def list_vendor_indicators(self) -> Iterator[VendorIndicator]:
        """Read the indicator items of the KV store collection back.

        Yields:
            One vendor indicator per item, identified by its key (OpenCTI id).

        Raises:
            requests.HTTPError: When the collection cannot be read.
            ValueError: When an item carries no key (never skipped: its deployment
                would look absent).
        """
        for item in self._kvstore.list_indicators():
            key = item.get("_key") if isinstance(item, Mapping) else None
            if not isinstance(key, str) or not key:
                raise ValueError("A KV store item of the read-back carries no _key")
            yield VendorIndicator(
                indicator_id=key,
                external_id=key,
                value=_text(item.get("values")),
                raw=item,
                # A failed update keeps the previous item: it never confirms the
                # current pattern of the indicator.
                pattern=_text(item.get("pattern")),
            )

    def remove_vendor_indicator(
        self, vendor_indicator: VendorIndicator, deployment: IndicatorDeployment
    ) -> None:
        """Delete an indicator item from the KV store collection.

        Args:
            vendor_indicator: The KV store item, as listed.
            deployment: The deployment requesting the removal.

        Raises:
            ValueError: When the item has no key.
            requests.HTTPError: When Splunk refuses the deletion.
        """
        key = vendor_indicator.external_id or vendor_indicator.indicator_id
        if not key:
            raise ValueError("The KV store item has no key")
        self._kvstore.delete(key)

    def push_indicator(self, stix_indicator: dict[str, Any]) -> str | None:
        """Write an indicator to the KV store again (analyst retry).

        Args:
            stix_indicator: The indicator in the stream event shape.

        Returns:
            The KV store key of the item.

        Raises:
            SplunkDeploymentError: When Splunk refuses the item or cannot be reached,
                with the reason OpenCTI shows (the connector logs the response).
        """
        try:
            return self._push_indicator(stix_indicator)
        except requests.RequestException as err:
            raise SplunkDeploymentError(failure_reason(err)) from err

    def collect_hits(
        self,
        deployments: Sequence[IndicatorDeployment],
        since: datetime,
    ) -> list[VendorHit] | HitCollection:
        """Read the matches of the KV store indicators from the saved search.

        Args:
            deployments: The live deployments.
            since: Start of the time range of the search.

        Returns:
            The hits, identified by OpenCTI id (KV store key) or matched value. When
            the result limit is reached, the results being sorted oldest first, the
            collection is complete until the newest result read. When every result
            read is at `since`, the read is not continued within that instant (a
            row count would move with late or deleted events): its hits are a lower
            bound and the next read starts just after it.

        Raises:
            requests.HTTPError: When the saved search cannot be run.
            ValueError: When a result is not an object or carries no `_time` (never
                skipped: the hit window would move past it).
        """
        if self._hits_saved_search is None or not deployments:
            return []
        rows = self._kvstore.run_saved_search(
            self._hits_saved_search, since, self._hits_max_results
        )
        hits: list[VendorHit] = []
        newest = since
        for row in rows:
            timestamp = (
                parse_splunk_time(row.get("_time"))
                if isinstance(row, Mapping)
                else None
            )
            if timestamp is None:
                raise ValueError("A result of the hits saved search carries no _time")
            if timestamp < since:
                continue
            newest = max(newest, timestamp)
            opencti_id = _text(row.get("opencti_id"))
            value = _text(row.get("value"))
            if opencti_id is None and value is None:
                continue
            hits.append(
                VendorHit(
                    timestamp=timestamp,
                    indicator_id=opencti_id,
                    external_id=opencti_id,
                    value=value,
                    count=_count(row.get("count")),
                )
            )
        if len(rows) >= self._hits_max_results:
            return HitCollection(hits=hits, complete_until=newest)
        return hits


def build_deployment_assurance(
    helper: "OpenCTIConnectorHelper",
    settings: "ConnectorSettings",
    kvstore: "KVStore",
    push_indicator: Callable[[dict[str, Any]], str | None],
) -> DeploymentAssurance:
    """Build the deployment write-back of the connector (reconciliation and hits).

    Args:
        helper: The connector helper.
        settings: The connector settings (`deployment`, `hits`, `security_platform`
            and `splunk.hits_saved_search`).
        kvstore: The KV store client of the connector.
        push_indicator: The stream create path of the connector (re-push).

    Returns:
        The deployment write-back, a no-op when `DEPLOYMENT_REPORTING_ENABLED` is false.
    """
    hits_saved_search = settings.splunk.hits_saved_search
    if (
        settings.deployment.reporting_enabled
        and settings.hits.reporting_enabled
        and not hits_saved_search
    ):
        helper.log_info(
            "hits are not collected (SPLUNK_HITS_SAVED_SEARCH is not configured)"
        )
    return DeploymentAssurance.from_settings(
        helper,
        settings,
        adapter=SplunkKVStoreDeploymentAdapter(
            kvstore,
            push_indicator=push_indicator,
            hits_saved_search=hits_saved_search,
        ),
    )
