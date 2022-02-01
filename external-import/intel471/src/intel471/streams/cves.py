from typing import Iterator

from stix2 import Bundle

import titan_client
from .common import Intel471Stream


class Intel471CVEsStream(Intel471Stream):
    def get_bundle(self) -> Iterator[Bundle]:
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = titan_client.VulnerabilitiesApi(api_client)
            api_response = api_instance.cve_reports_get(_from=1622505600000, count=2)
        return api_response.to_stix()
