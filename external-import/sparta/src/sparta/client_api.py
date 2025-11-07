import json
import ssl
import urllib
from typing import Optional


class SpartaClient:
    def __init__(self, helper, config):
        """Initialize the client with necessary configurations"""
        self.helper = helper
        self.config = config
        self.base_url = self.config.sparta.base_url

    def retrieve_data(self) -> Optional[dict]:
        try:
            # Fetch json bundle from SPARTA
            serialized_bundle = (
                urllib.request.urlopen(
                    str(self.base_url),
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
            # Convert the data to python dictionary
            stix_bundle = json.loads(serialized_bundle)
            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.connector_logger.error(
                "Error retrieving url",
                {"base_url": self.base_url, "error": urllib_error},
            )
            self.helper.metric.inc("client_error_count")

        except json.JSONDecodeError:
            # Sparta does not return 404 if the url does not exists
            # To prevent error, we check if
            self.helper.connector_logger.warning(
                "URL does not contains a valid json", {"base_url": self.base_url}
            )
        return None
