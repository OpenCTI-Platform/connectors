from urllib.parse import parse_qs, urlparse

from .base_api import BaseCrowdstrikeClient


class IndicatorsAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_indicator_entities(
        self, limit: int, sort: str, fql_filter: str, deep_pagination: bool
    ) -> dict:
        """
        Get info about indicators that match provided FQL filters.
        :param limit: Maximum number of records to return (Max: 5000) in integer
        :param sort: The property to sort by. (Ex: created_date|desc) in str
        :param fql_filter: FQL query expression that should be used to limit the results in str
        :param deep_pagination: Boolean
        :return: Dict object containing API response
        """
        response = self.cs_intel.query_indicator_entities(
            limit=limit, sort=sort, filter=fql_filter, deep_pagination=deep_pagination
        )

        response_body = response["body"]
        response_body["next_page_details"] = None

        next_page_details = self.get_next_page(response)

        if next_page_details is not None:
            response_body["next_page_details"] = next_page_details

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined indicator entities...")

        return response_body

    @staticmethod
    def get_next_page(response: dict) -> dict | None:
        """
        Get the next page of indicators if the total number is higher than the limit chosen
        :param response: dict of the response
        :return: A dictionary if there is more indicators than limit set or None
        """
        next_page = response.get("headers").get("Next-Page")

        if next_page is not None:
            enc_payload = urlparse(next_page).query
            next_page_parsed = parse_qs(enc_payload)

            return next_page_parsed
        else:
            return None
