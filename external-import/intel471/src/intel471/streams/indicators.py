from typing import Iterator

from stix2 import Bundle

import titan_client
from .common import Intel471Stream


class Intel471IndicatorsStream(Intel471Stream):

    # TODO: Dynamic initial TS based on now
    # TODO: allow setting up custom start TS
    initial_from_ts = 1643666400000

    def get_bundle(self) -> Iterator[Bundle]:
        cursor = (self.helper.get_state() or {}).get("indicators_cursor")
        # TODO: Store ISO date for visibility
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = titan_client.IndicatorsApi(api_client)
        while True:
            kwargs = {"_from": self.initial_from_ts, "count": 60}
            if cursor:
                kwargs["cursor"] = cursor
            api_response = api_instance.indicators_stream_get(**kwargs)
            if not api_response.indicators:
                break
            cursor = api_response.cursor_next
            self.helper.set_state({"indicators_cursor": cursor})  # TODO: not thread safe
            # TODO: handle empty bundles
            yield api_response.to_stix()
