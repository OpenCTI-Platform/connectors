from typing import Iterator

from stix2 import Bundle

import titan_client
from titan_client.titan_stix.exceptions import EmptyBundle
from .common import Intel471Stream


class Intel471CVEsStream(Intel471Stream):

    ref = "cves"

    def get_bundle(self) -> Iterator[Bundle]:
        state = self.helper.get_state() or {}
        cursor = state.get(self.cursor_name)
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = titan_client.VulnerabilitiesApi(api_client)
        while True:
            kwargs = {"_from": self.initial_history, "sort": "earliest", "count": 100}
            if cursor:
                kwargs["_from"] = cursor
            self.helper.log_info("{} calls Titan API with arguments: {}.".format(self.__class__.__name__, str(kwargs)))
            api_response = api_instance.cve_reports_get(**kwargs)
            self.helper.log_info("{} got {} items from Titan API.".format(
                self.__class__.__name__,
                len(api_response.cve_reports or [])))
            if not api_response.cve_reports:
                break
            cursor = api_response.cve_reports[-1].activity.last + 1
            state[self.cursor_name] = cursor
            self.helper.set_state(state)
            try:
                bundle = api_response.to_stix()
            except EmptyBundle:
                self.helper.log_info(f"{self.__class__.__name__} got empty bundle from STIX converter.")
            else:
                yield bundle
