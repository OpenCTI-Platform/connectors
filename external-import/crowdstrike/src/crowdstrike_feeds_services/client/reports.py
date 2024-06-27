from .base_api import BaseCrowdstrikeClient


class ReportsAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_report_entities(
        self, limit: int, offset: int, sort: str, fql_filter: str, fields: list
    ) -> dict:
        """
        Get info about reports that match provided FQL filters
        :param limit: Maximum number of records to return (Max: 5000) in integer
        :param offset: Starting index of overall result set from which to return ids in integer
        :param sort: The property to sort by. (Ex: created_date|desc) in str
        :param fql_filter: FQL query expression that should be used to limit the results in str
        :param fields: The fields to return, or a predefined set of fields in the form of the collection name
        surrounded by two underscores like: __<collection>__. Ex: slug __full__. Defaults to __basic__.
        :return: Dict object containing API response
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
        :return: Dict object containing API response
        """

        response = self.cs_intel.get_report_entities(ids=ids, fields=fields)

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting report entities...")

        return response["body"]

    def get_report_pdf(self, report_id: str):
        """
        Return a Report PDF attachment
        :param report_id: ID of a report in string
        :return: Binary object on SUCCESS, dict object containing API response on FAILURE
        """
        response = self.cs_intel.get_report_pdf(id=report_id)

        if type(response) is dict:
            self.handle_api_error(response)

        self.helper.connector_logger.info("Getting report PDF...")

        return response
