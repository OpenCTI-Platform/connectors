from datetime import datetime
from typing import Optional

from pydantic import ValidationError
from pymisp import PyMISP, PyMISPError
from api_client.models import EventRestSearchListItem


class MISPClientError(Exception):
    """Custom exception for MISP client errors."""


class MISPClient:
    def __init__(
        self,
        url: str,
        key: str,
        verify_ssl: bool = False,
        certificate: Optional[str] = None,
    ):
        self._client = PyMISP(
            url=url,
            key=key,
            cert=certificate,
            ssl=verify_ssl,
            debug=False,
            tool="OpenCTI MISP connector",
        )

    def search_events(
        self,
        date_attribute_filter: str,
        date_value_filter: datetime,
        keyword: str,
        included_tags: list,
        excluded_tags: list,
        enforce_warning_list: bool,
        with_attachments: bool,
        limit: int,
        page: int,
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

                # self.helper.log_info(
                #     "Fetching MISP events with args: " + json.dumps(kwargs)
                # )

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
                    **{date_attribute_filter: date_value_filter},
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
                        # self.helper.log_error(str(err))
                        print(f"Validation error: {err}")
                        continue

                current_page += 1
            except PyMISPError as err:
                raise MISPClientError(f"Error searching events in MISP: {err}") from err
            # TODO: add a retry mechanism

        return events
