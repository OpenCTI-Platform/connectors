from typing import Any, Union

from .common import Intel471Stream


class Intel471IndicatorsStream(Intel471Stream):

    label = "indicators"
    api_payload_objects_key = "indicators"
    api_class_name = "IndicatorsApi"
    api_method_name = "indicators_stream_get"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"_from": self.initial_history, "count": 100}
        if cursor:
            kwargs["cursor"] = cursor
        return kwargs

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return api_response.cursor_next
