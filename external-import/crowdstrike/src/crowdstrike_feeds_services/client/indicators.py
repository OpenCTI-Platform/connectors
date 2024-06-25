from urllib.parse import parse_qs, urlparse

from .base_api import BaseCrowdstrikeClient


class IndicatorsAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_indicator_entities(
        self, limit, sort, fql_filter, deep_pagination
    ) -> dict:

        response = self.cs_intel.query_indicator_entities(
            limit=limit, sort=sort, filter=fql_filter, deep_pagination=deep_pagination
        )

        response_body = response["body"]
        response_body["next_page_details"] = None

        next_page_details = self.get_next_page(response)

        if next_page_details is not None:
            response_body["next_page_details"] = next_page_details

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response_body

    @staticmethod
    def get_next_page(response):
        next_page = response.get("headers").get("Next-Page")

        if next_page is not None:
            enc_payload = urlparse(next_page).query
            next_page_parsed = parse_qs(enc_payload)

            return next_page_parsed
        else:
            return None
