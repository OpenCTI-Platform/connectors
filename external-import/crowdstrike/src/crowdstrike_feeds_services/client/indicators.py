from typing import TYPE_CHECKING

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
    ) -> dict:
        """Get info about indicators that match provided FQL filters.

        Thin wrapper around the FalconPy ``QueryIntelIndicatorEntities``
        operation (``GET /intel/combined/indicators/v1``). The only
        keyword arguments accepted by that operation are ``fields``,
        ``filter``, ``include_deleted``, ``include_relations``, ``limit``,
        ``offset``, ``parameters``, ``q`` and ``sort`` — there is no
        ``deep_pagination`` flag and no continuation-token parameter, and
        the response carries no ``Next-Page`` HTTP header. Deep pagination
        is handled by the caller via the ``_marker`` FQL field (see the
        importer for the loop). Keeping this method *single-page* avoids
        re-introducing the silently-ignored ``deep_pagination`` / ``next_page``
        keywords that previously caused the connector to only ever fetch
        the first page.

        :param limit: Maximum number of records to return (max: 5000).
        :param sort: The property to sort by (e.g. ``_marker.asc``).
        :param fql_filter: FQL query expression used to filter the results.
        :return: Parsed response body (``response["body"]``).
        """
        response = self.cs_intel.query_indicator_entities(
            limit=limit, sort=sort, filter=fql_filter
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined indicator entities...")

        # ``handle_api_error`` normalises ``response["body"]`` to ``{}``
        # when the upstream omits it, but we still guard here so the
        # contract is explicit at the call site.
        return response.get("body") or {}
