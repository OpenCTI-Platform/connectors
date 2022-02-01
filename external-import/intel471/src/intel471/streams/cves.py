from typing import Iterator

from stix2 import Bundle

import titan_client
from .common import Intel471Stream


class Intel471CVEsStream(Intel471Stream):
    def get_bundle(self) -> Iterator[Bundle]:
        state = self.helper.get_state() or {}
        cursor = state.get("cves_cursor")
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = titan_client.VulnerabilitiesApi(api_client)
        while True:
            # kwargs = {"_from": self.lookback, "count": 100}
            kwargs = {"_from": "1days", "sort": "earliest", "count": 1}
            if cursor:
                kwargs["_from"] = cursor
            api_response = api_instance.cve_reports_get(**kwargs)
            self.helper.log_info("{} got {} items from Titan API.".format(
                self.__class__.__name__,
                len(api_response.cve_reports or [])))
            if not api_response.cve_reports:
                break
            cursor = api_response.cve_reports[-1].activity.last + 1
            state["cves_cursor"] = cursor
            self.helper.set_state(state)  # TODO: not thread safe
            yield api_response.to_stix()
