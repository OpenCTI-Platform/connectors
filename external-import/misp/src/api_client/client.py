import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Generator
from warnings import warn

import urllib3
from api_client.models import EventRestSearchListItem
from pydantic import HttpUrl, ValidationError
from pymisp import PyMISP, PyMISPError
from requests.adapters import HTTPAdapter, Retry

_default_logger = logging.getLogger(__name__)


class MISPClientError(Exception):
    """Custom exception for MISP client errors."""


class MISPClient:
    """Wrapper of PyMISP client."""

    def __init__(
        self,
        url: HttpUrl,
        key: str,
        timeout: float | None,
        verify_ssl: bool = False,
        certificate: str | None = None,
        retry: int = 3,
        backoff: timedelta = timedelta(seconds=1),
        logger: Any = None,
    ):
        """Initialize and wrap a PyMISP instance."""

        # Any logger with debug(message), info(message) and warning(message),
        # e.g. the connector helper's connector_logger.
        self._logger = logger or _default_logger
        # Which `date_from` value MISP answered last: False for the datetime
        # (PyMISP sends a Unix timestamp), True for the YYYY-MM-DD string.
        # Remembered for the next runs, so the format that works is tried first.
        self._date_from_as_date_string = False
        # Whether either `date_from` format has ever returned events on this
        # client. Until it has, an empty first page in both formats is a
        # warning (the instance may accept neither); after that, it only means
        # nothing is new and is logged at info level.
        self._date_from_ever_answered = False

        retry_strategy = Retry(
            total=retry,
            backoff_factor=backoff.total_seconds(),
            allowed_methods=None,  # allow retry on any verb
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
            raise_on_status=False,  # let PyMISP handle the response
        )
        http_adapter = HTTPAdapter(max_retries=retry_strategy)

        if not verify_ssl:
            # Certificate verification was turned off on purpose: urllib3 would
            # otherwise emit an InsecureRequestWarning on every request, through
            # warnings.warn() to stderr, bypassing CONNECTOR_LOG_LEVEL.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._client = PyMISP(
            url=str(url),
            key=key,
            cert=certificate,
            ssl=verify_ssl,
            debug=False,
            tool="OpenCTI MISP connector",
            https_adapter=http_adapter,
            timeout=timeout,
        )

    def _sanitize_user_id_in_tags(self, obj):
        """
        Recursively replace boolean user_id values with the string "unknown".
        Works for structures where Tag objects can appear under Event.Tag,
        Attribute.Tag, Object.Attribute.Tag, etc.
        """
        if isinstance(obj, dict):
            if "user_id" in obj and isinstance(obj["user_id"], bool):
                obj["user_id"] = "unknown"
            for v in obj.values():
                self._sanitize_user_id_in_tags(v)
        elif isinstance(obj, list):
            for it in obj:
                self._sanitize_user_id_in_tags(it)

    @staticmethod
    def _to_utc_date_string(value: date) -> str:
        """Format a date or a datetime (converted to UTC first) as YYYY-MM-DD."""
        if isinstance(value, datetime):
            value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%d")

    def search_events(
        self,
        date_field_filter: str,
        date_value_filter: datetime,
        datetime_attribute: str,
        keyword: str,
        included_tags: list,
        excluded_tags: list,
        included_org_creators: list,
        excluded_org_creators: list,
        enforce_warning_list: bool,
        with_attachments: bool,
        limit: int,
        page: int = 1,
    ) -> Generator[EventRestSearchListItem, None, None]:
        """
        Search for events in MISP with the given parameters.
        """
        current_page = page
        is_date_from = date_field_filter == "date_from"

        # `date_from` (MISP `from`): PyMISP turns a datetime into a Unix
        # timestamp. Whether MISP accepts it depends on the MISP version: some
        # versions return events for it, others return [] without error and
        # only match a YYYY-MM-DD date. So the first page is tried with each
        # format until one returns events, and the following pages keep that
        # format, so the format never changes in the middle of a pagination.
        candidates = [date_value_filter]
        if is_date_from:
            candidates.append(self._to_utc_date_string(date_value_filter))
            if self._date_from_as_date_string:
                candidates.reverse()
        order = "Event.id ASC" if is_date_from else f"Event.{datetime_attribute} ASC"
        date_value = None

        while True:
            try:
                tags_query = self._client.build_complex_query(
                    or_parameters=included_tags,
                    not_parameters=excluded_tags,
                )

                org_creators_query = self._client.build_complex_query(
                    or_parameters=included_org_creators,
                    not_parameters=excluded_org_creators,
                )

                def search_page(value):
                    self._logger.debug(
                        f"MISP restSearch page {current_page}: "
                        f"{date_field_filter}={value!r} ({type(value).__name__})"
                    )
                    results = self._client.search(
                        controller="events",
                        return_format="json",
                        value=keyword,
                        searchall=True if keyword else None,
                        tags=tags_query or None,
                        org=org_creators_query or None,
                        enforce_warninglist=enforce_warning_list,
                        with_attachments=with_attachments,
                        limit=limit,
                        page=current_page,
                        # Undocumented parameter to sort the results by the given attribute
                        # https://www.circl.lu/doc/misp/automation/#:~:text=Example-,Search,-Events%20management
                        order=order,
                        **{date_field_filter: value},
                    )
                    if isinstance(results, dict) and results.get("errors"):
                        status_code, error_message = results.get("errors")
                        raise MISPClientError(
                            error_message,
                            {"status_code": status_code, "response": results},
                        )
                    return results

                if date_value is None:
                    # First page: try each candidate until one returns events.
                    results = []
                    for candidate in candidates:
                        results = search_page(candidate)
                        if len(results) > 0:
                            date_value = candidate
                            if is_date_from:
                                self._date_from_as_date_string = isinstance(
                                    candidate, str
                                )
                                self._date_from_ever_answered = True
                            break
                    if len(results) == 0:
                        if is_date_from and self._date_from_ever_answered:
                            self._logger.info(
                                f"MISP returned no new event for date_from "
                                f"{date_value_filter!r}."
                            )
                        elif is_date_from:
                            self._logger.warning(
                                f"MISP returned no event for date_from "
                                f"{date_value_filter!r}, sent both as a Unix "
                                f"timestamp and as "
                                f"{self._to_utc_date_string(date_value_filter)!r}, "
                                f"and neither format has returned events yet. "
                                f"Either nothing is new, or this MISP instance "
                                f"accepts neither format."
                            )
                        break
                else:
                    results = search_page(date_value)

                # Break if no more result
                if len(results) == 0:
                    break

                for result in results:
                    try:
                        self._sanitize_user_id_in_tags(result)
                        yield EventRestSearchListItem(**result)
                    except ValidationError as err:
                        event_id = result.get("Event", {}).get("id", "unknown")
                        warn(
                            f"MISP event data seems malformed, skipping it (event id = {event_id}). "
                            f"Validation error: {err}",
                            UserWarning,
                            stacklevel=3,
                        )
                        continue

                current_page += 1
            except PyMISPError as err:
                raise MISPClientError(f"Error searching events in MISP: {err}") from err
