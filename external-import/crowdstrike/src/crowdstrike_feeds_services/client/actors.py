from typing import Any, Optional, cast

from .base_api import BaseCrowdstrikeClient


class ActorsAPI(BaseCrowdstrikeClient):
    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_actor_entities(
        self,
        limit: int,
        offset: int,
        sort: str | None = None,
        fql_filter: str | None = None,
        fields: str | list[str] | None = "__basic__",
    ) -> Optional[dict]:
        """
        Get info about actors that match provided FQL filters.
        :param limit: Maximum number of records to return (Max: 5000) in integer
        :param offset: Starting index of overall result set from which to return ids in integer
        :param sort: The property to sort by. (Ex: created_date|desc) in str
        :param fql_filter: FQL query expression that should be used to limit the results in str
        :param fields: The fields to return, or a predefined set of fields in the form of the collection name
        surrounded by two underscores like: __<collection>__. Ex: slug __full__. Defaults to __basic__.
        :return: Dict object containing API response
        """

        # Build kwargs so we don't send None values to the SDK/client.
        kwargs: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "fields": "__basic__" if fields is None else fields,
        }
        if sort is not None:
            kwargs["sort"] = sort
        if fql_filter is not None:
            kwargs["filter"] = fql_filter

        response = self.cs_intel.query_actor_entities(parameters=kwargs)

        self.handle_api_error(cast(dict[str, Any], response))
        self.helper.connector_logger.debug(
            "ActorsAPI.get_combined_actor_entities",
            {
                "limit": limit,
                "offset": offset,
                "sort": sort,
                "fql_filter": fql_filter,
                "fields": fields,
            },
        )
        self.helper.connector_logger.info("Getting combined actor entities...")

        body = cast(dict[str, Any], response).get("body")
        return body

    def query_mitre_attacks(self, actor_id: int):
        """
        Query MITRE ATT&CK techniques associated with a specific threat actor.
        :param actor_id: The ID for the threat actor
        :return: Dict object containing API response with TTP data in format:
                 {'errors': [], 'meta': {...}, 'resources': ['actor_TA0001_T1190', ...]}
        """
        response = self.cs_intel.query_mitre_attacks(id=str(actor_id))

        self.handle_api_error(cast(dict[str, Any], response))
        self.helper.connector_logger.info(
            f"Getting MITRE attacks for actor ID: {actor_id}..."
        )

        body = cast(dict[str, Any], response).get("body")
        return body
