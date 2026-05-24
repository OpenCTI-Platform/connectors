from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlparse

from .base_api import BaseCrowdstrikeClient

if TYPE_CHECKING:
    from crowdstrike_feeds_connector import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class IndicatorsAPI(BaseCrowdstrikeClient):

    def __init__(self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"):
        super().__init__(config, helper)

    def get_combined_indicator_entities(
        self,
        limit: int,
        sort: str,
        fql_filter: str,
        deep_pagination: bool,
        next_page: Optional[str] = None,
    ) -> dict:
        """Get info about indicators that match provided FQL filters.

        :param limit: Maximum number of records to return (max: 5000).
        :param sort: The property to sort by (e.g. ``created_date|desc``).
        :param fql_filter: FQL query expression used to filter the results.
        :param deep_pagination: Whether to enable CrowdStrike's deep pagination.
        :param next_page: Continuation token returned by a previous call as
            ``response_body["next_page"]``. Pass ``None`` for the first page.
        :return: Parsed response body, augmented with a ``next_page`` key whose
            value is either the next-page token (string) or ``None`` when the
            iteration is complete.
        """
        kwargs = {
            "limit": limit,
            "sort": sort,
            "filter": fql_filter,
            "deep_pagination": deep_pagination,
        }
        if next_page:
            kwargs["next_page"] = next_page

        response = self.cs_intel.query_indicator_entities(**kwargs)

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined indicator entities...")

        # ``handle_api_error`` normalises ``response["body"]`` to ``{}``
        # when the upstream omits it (or returns ``None``), but we still
        # use ``.get(...) or {}`` here so the read is robust even if
        # ``handle_api_error`` is ever refactored to drop the in-place
        # normalisation, and so a static reader can see the contract on
        # the call site without grepping the base class.
        response_body = response.get("body") or {}
        response_body["next_page"] = self.get_next_page(response)

        return response_body

    @staticmethod
    def get_next_page(response: dict) -> Optional[str]:
        """Extract the next-page continuation token from a response.

        CrowdStrike exposes pagination through a ``Next-Page`` HTTP header that
        contains a URL whose query string carries the ``next_page`` parameter.
        We extract that value and return it as-is so it can be passed back to
        :meth:`get_combined_indicator_entities`. Returns ``None`` when there
        is no next page.
        """
        headers = response.get("headers") or {}
        next_page_url = headers.get("Next-Page")
        if not next_page_url:
            return None

        parsed_query = parse_qs(urlparse(next_page_url).query)
        token_values = parsed_query.get("next_page") or []
        if not token_values:
            return None

        token = token_values[0]
        return token or None
