from .base_api import BaseCrowdstrikeClient


class ActorsAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_actor_entities(self, limit, offset, sort, fql_filter, fields):

        response = self.cs_intel.query_actor_entities(
            limit=limit, offset=offset, sort=sort, filter=fql_filter, fields=fields
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response["body"]
