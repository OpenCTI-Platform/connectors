from datetime import datetime
from typing import Any, Optional, cast

from .base_api import BaseCrowdstrikeClient


class RulesAPI(BaseCrowdstrikeClient):

    def __init__(self, helper):
        super().__init__(helper)

    def get_latest_rule_file(
        self,
        rule_set_type: str,
        e_tag: Optional[str] = None,
        last_modified: Optional[datetime] = None,
    ) -> dict | bytes:
        """
        Download the latest rule set,
        :param rule_set_type: The rule news report type in string
        :param e_tag: Optional. Download the latest rule set only if it doesn't have an ETag
        matching the given ones in string
        :param last_modified: Optional. Download the latest rule set only if the rule was modified after this date in datetime
        :return: Binary object on SUCCESS defaults format is zip, dict object containing API response on FAILURE
        """
        kwargs: dict[str, Any] = {"type": rule_set_type}
        if e_tag is not None:
            kwargs["if_none_match"] = e_tag
        if last_modified is not None:
            kwargs["if_modified_since"] = last_modified

        response: Any = self.cs_intel.get_latest_rule_file(**kwargs)

        if isinstance(response, dict):
            self.handle_api_error(response)
        self.helper.connector_logger.info("Getting latest rule file for Yara Master...")

        return cast(dict | bytes, response)
