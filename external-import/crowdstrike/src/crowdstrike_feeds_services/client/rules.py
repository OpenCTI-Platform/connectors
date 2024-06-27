from datetime import datetime

from .base_api import BaseCrowdstrikeClient


class RulesAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_latest_rule_file(
        self, rule_set_type: str, e_tag: str, last_modified: datetime
    ) -> dict | bytes:
        """
        Download the latest rule set,
        :param rule_set_type: The rule news report type in string
        :param e_tag: Download the latest rule set only if it doesn't have an ETag
        matching the given ones in string
        :param last_modified: Download the latest rule set only if the rule was modified after this date in datetime
        :return: Binary object on SUCCESS defaults format is zip, dict object containing API response on FAILURE
        """
        response = self.cs_intel.get_latest_rule_file(
            type=rule_set_type, if_none_match=e_tag, if_modified_since=last_modified
        )

        if type(response) is dict:
            self.handle_api_error(response)
        self.helper.connector_logger.info("Getting latest rule file for Yara Master...")

        return response
