from .base_api import BaseCrowdstrikeClient


class RulesAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_latest_rule_file(self, rule_set_type, e_tag, last_modified):

        response = self.cs_intel.get_latest_rule_file(
            type=rule_set_type, if_none_match=e_tag, if_modified_since=last_modified
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting latest rule file for Yara Master...")

        return response["body"]
