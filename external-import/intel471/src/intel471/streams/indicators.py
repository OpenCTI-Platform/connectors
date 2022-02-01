import datetime
from typing import Iterator

from stix2 import Bundle

import titan_client
from titan_client.titan_stix.exceptions import EmptyBundle
from .common import Intel471Stream


class Intel471IndicatorsStream(Intel471Stream):
    def get_bundle(self) -> Iterator[Bundle]:
        state = self.helper.get_state() or {}
        cursor = state.get("indicators_cursor")
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = titan_client.IndicatorsApi(api_client)
        while True:
            # TODO: ensure _from doesn't matter when cursor is provided
            kwargs = {"_from": self.lookback, "count": 100}
            if cursor:
                kwargs["cursor"] = cursor
            api_response = api_instance.indicators_stream_get(**kwargs)
            self.helper.log_info("{} got {} items from Titan API.".format(
                self.__class__.__name__,
                len(api_response.cve_reports or [])))
            if not api_response.indicators:
                break
            cursor = api_response.cursor_next
            state["indicators_cursor"] = cursor
            self.helper.set_state(state)  # TODO: not thread safe
            try:
                bundle = api_response.to_stix()
            except EmptyBundle:
                self.helper.log_info(f"{self.__class__.__name__} got empty bundle from STIX converter.")
            else:
                yield bundle
