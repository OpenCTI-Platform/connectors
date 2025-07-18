from datetime import datetime, timedelta
from typing import Optional
from warnings import warn

from api_client.models import EventRestSearchListItem
from pydantic import ValidationError
from pymisp import PyMISP, PyMISPError
from requests.adapters import HTTPAdapter, Retry


class MISPClientError(Exception):
    """Custom exception for MISP client errors."""


class MISPClient:
    """Wrapper of PyMISP client."""

    def __init__(
        self,
        url: str,
        key: str,
        verify_ssl: bool = False,
        certificate: Optional[str] = None,
        retry: int = 3,
        backoff: timedelta = timedelta(seconds=1),
    ):
        """Initialize and wrap a PyMISP instance."""

        retry_strategy = Retry(
            total=retry,
            backoff_factor=backoff.total_seconds(),
            allowed_methods=None,  # allow retry on any verb
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
            raise_on_status=False,  # let PyMISP handle the response
        )
        http_adapter = HTTPAdapter(max_retries=retry_strategy)

        self._client = PyMISP(
            url=url,
            key=key,
            cert=certificate,
            ssl=verify_ssl,
            debug=False,
            tool="OpenCTI MISP connector",
            https_adapter=http_adapter,
        )

    def search_events(
        self,
        date_field_filter: str,
        date_value_filter: datetime,
        keyword: str,
        included_tags: list,
        excluded_tags: list,
        enforce_warning_list: bool,
        with_attachments: bool,
        limit: int = 10,
        page: int = 1,
    ) -> list[EventRestSearchListItem]:
        """
        Search for events in MISP with the given parameters.
        """
        events = []
        current_page = page

        while True:
            try:
                tags_query = self._client.build_complex_query(
                    or_parameters=included_tags,
                    not_parameters=excluded_tags,
                )

                # MISP API doesn't provide a way to sort the results.
                # Events are always returned sorted by Event.id ASC,
                # which is **NOT** equivalent to sorted by Event.date (creation date) ASC
                results = self._client.search(
                    controller="events",
                    return_format="json",
                    value=keyword,
                    searchall=True if keyword else None,
                    tags=tags_query,
                    enforce_warninglist=enforce_warning_list,
                    with_attachments=with_attachments,
                    limit=limit,
                    page=current_page,
                    **{date_field_filter: date_value_filter},
                )
                if isinstance(results, dict) and results.get("errors"):
                    status_code, error_message = results.get("errors")
                    raise MISPClientError(
                        error_message, {"status_code": status_code, "response": results}
                    )

                # Break if no more result
                if len(results) == 0:
                    break

                for result in results:
                    try:
                        events.append(EventRestSearchListItem(**result))
                    except ValidationError as err:
                        warn(
                            f"MISP event data seems malformed, skipping it. Validation error: {err}",
                            UserWarning,
                            stacklevel=3,
                        )
                        continue

                current_page += 1
            except PyMISPError as err:
                raise MISPClientError(f"Error searching events in MISP: {err}") from err

        return events
