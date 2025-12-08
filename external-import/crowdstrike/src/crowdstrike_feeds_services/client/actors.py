from .base_api import BaseCrowdstrikeClient
from typing import List, Optional


class ActorsAPI(BaseCrowdstrikeClient):
    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_actor_entities(
        self, limit: int, offset: int, sort: str, fql_filter: str, fields: list
    ):
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

        response = self.cs_intel.query_actor_entities(
            limit=limit, offset=offset, sort=sort, filter=fql_filter, fields=fields
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response["body"]

    def query_mitre_attacks(self, actor_id: int):
        """
        Query MITRE ATT&CK techniques associated with a specific threat actor.
        :param actor_id: The ID for the threat actor
        :return: Dict object containing API response with TTP data in format:
                 {'errors': [], 'meta': {...}, 'resources': ['actor_TA0001_T1190', ...]}
        """
        response = self.cs_intel.query_mitre_attacks(id=str(actor_id))

        self.handle_api_error(response)
        self.helper.connector_logger.info(
            f"Getting MITRE attacks for actor ID: {actor_id}..."
        )

        return response["body"]

    def get_actors_by_slugs(
        self,
        slugs: List[str],
        fields: Optional[List[str]] = None,
    ):
        """
        Resolve one or more threat actors by their slug values as provided
        in indicator/report collections.
        """
        cleaned_slugs = [s for s in slugs if s]
        if not cleaned_slugs:
            return {"errors": [], "meta": {}, "resources": []}

        if fields is None:
            # Start with basic – can switch to "__full__" if you need more.
            fields = ["__full__"]

        fql_filter = self.build_slug_filter(cleaned_slugs)

        return self.get_combined_actor_entities(
            limit=len(cleaned_slugs),
            offset=0,
            sort="last_modified_timestamp|desc",
            fql_filter=fql_filter,
            fields=fields,
        )

    @staticmethod
    def build_slug_filter(slugs: List[str]) -> str:
        """
        Build an FQL filter to match threat actors by slug.
        Uses OR semantics between slugs so that any matching slug is returned.
        Example output: "(slug:'LABYRINTHCHOLLIMA',slug:'WICKEDPANDA')"
        """
        cleaned_slugs = [s for s in slugs if s]
        if not cleaned_slugs:
            return ""

        conditions = [f"slug:'{slug}'" for slug in cleaned_slugs]
        # CrowdStrike FQL uses comma as OR between clauses.
        return "(" + ",".join(conditions) + ")"
