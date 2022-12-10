"""OpenCTI Cybersixgill client module."""

import re

from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_feed_client import SixgillFeedClient
from sixgill.sixgill_utils import is_indicator

from .utils.constants import CHANNEL_ID

__all__ = [
    "CybersixgillClient",
]

opencti_mapping = {
    "ipv4-addr": "IPv4",
    "domain-name": "domain",
    "domain": "domain",
    "url": "URL",
    "file": "File",
}


class CybersixgillClient:
    """Cybersixgill client."""

    def __init__(self, client_id: str, client_secret: str, bulk_size: int) -> None:
        """
        Initializer.
        :param client_id: Cybersixgill Client ID.
        :param client_secret: Cybersixgill Client Secret.
        """

        self.client_server = SixgillFeedClient(
            client_id=client_id,
            client_secret=client_secret,
            channel_id=CHANNEL_ID,
            feed_stream=FeedStream.DARKFEED,
            bulk_size=bulk_size,
            verify=True,
        )

    def get_darkfeed_data(self):
        """
        Get cybersixgill darkfeed data.
        :param modified_since: Filter by results modified since this date.
        :param limit: Return limit.
        :return: A list of darkfeed data.
        """
        raw_response = self.client_server.get_bundle()

        df_data = list(filter(is_indicator, raw_response.get("objects", [])))

        self.client_server.commit_indicators()

        return df_data

    @staticmethod
    def get_sixgill_pattern_type(indicator):
        """This method parses the 'Pattern' of the darkfeed to retrieve the IOC's

        Arguments:
            indicator - Cybersixgill Darkfeed Indicator

        Returns:
            list -- Key, Value pair of the retrived IOC's
        """
        stix_regex_parser = re.compile(
            r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?"
        )
        indicator_list = []
        final_indicator_type = ""
        if "pattern" in indicator:
            for indicator_type, sub_type, value in stix_regex_parser.findall(
                indicator.get("pattern")
            ):
                indicator_dict = {}
                indicator_type = opencti_mapping.get(indicator_type)
                if indicator_type.lower() == "file":
                    if "MD5" in sub_type:
                        indicator_dict.update({"Type": "FileHash-MD5", "Value": value})
                    if "SHA-1" in sub_type:
                        indicator_dict.update({"Type": "FileHash-SHA1", "Value": value})
                    if "SHA-256" in sub_type:
                        indicator_dict.update(
                            {"Type": "FileHash-SHA256", "Value": value}
                        )
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
                elif indicator_type.lower() == "url":
                    indicator_dict.update({"Type": "URL", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
                elif indicator_type.lower() == "ipv4":
                    indicator_dict.update({"Type": "IPv4", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
                elif indicator_type.lower() == "domain":
                    indicator_dict.update({"Type": "domain", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
        return indicator_list, final_indicator_type
