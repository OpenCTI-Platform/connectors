from typing import Iterator

from stix2 import Bundle

import titan_client
from titan_client.titan_stix.exceptions import EmptyBundle
from .common import Intel471Stream


class Intel471IndicatorsStream(Intel471Stream):

    ref = "indicators"

    def get_bundle(self) -> Iterator[Bundle]:
        state = self.helper.get_state() or {}
        cursor = state.get(self.cursor_name)
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = titan_client.IndicatorsApi(api_client)
        while True:
            kwargs = {"_from": self.initial_history, "count": 100}
            if cursor:
                kwargs["cursor"] = cursor
            self.helper.log_info("{} calls Titan API with arguments: {}.".format(self.__class__.__name__, str(kwargs)))
            api_response = api_instance.indicators_stream_get(**kwargs)
            self.helper.log_info("{} got {} items from Titan API.".format(
                self.__class__.__name__,
                len(api_response.indicators or [])))
            if not api_response.indicators:
                break
            cursor = api_response.cursor_next
            state[self.cursor_name] = cursor
            self.helper.set_state(state)
            try:
                bundle = api_response.to_stix()
            except EmptyBundle:
                self.helper.log_info(f"{self.__class__.__name__} got empty bundle from STIX converter.")
            else:
                yield bundle
