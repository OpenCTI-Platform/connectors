from .base_api import BaseCrowdstrikeClient


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
