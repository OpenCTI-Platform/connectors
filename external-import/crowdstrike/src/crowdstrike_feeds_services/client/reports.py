from .base_api import BaseCrowdstrikeClient


class ReportsAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_report_entities(
        self, limit: int, offset: int, sort: str, fql_filter: str, fields: list
    ) -> dict:
        """
        Get info about reports that match provided FQL filters
        :param limit: In
        :param offset:
        :param sort:
        :param fql_filter:
        :param fields:
        :return:
        """

        response = self.cs_intel.query_report_entities(
            limit=limit, offset=offset, sort=sort, filter=fql_filter, fields=fields
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response["body"]

    def get_report_entities(self, ids: list, fields: list):
        """
        Retrieve specific reports using their report IDs
        :param ids: List of IDs
        :param fields: List of fields
        """

        response = self.cs_intel.get_report_entities(ids=ids, fields=fields)

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response["body"]

    def get_report_pdf(self, report_id: str):
        """
        Return a Report PDF attachment
        :param report_id: ID of a report in string
        """

        response = self.cs_intel.get_report_pdf(id=report_id)

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response["body"]
