from typing import Any, Union

from .common import Intel471Stream


class Intel471IndicatorsStream(Intel471Stream):
    label = "indicators"
    api_payload_objects_key = "indicators"
    api_class_name = "IndicatorsApi"
    api_method_name = "indicators_stream_get"
    initial_history_key = "indicators_initdate"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"last_updated_from": self._get_initial_history(), "count": 100}
        if cursor:
            kwargs["cursor"] = cursor
        return kwargs

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return api_response.cursor_next

    def _get_initial_history(self):
        stored_initial_history = self._get_state(self.initial_history_key)
        if not stored_initial_history:
            stored_initial_history = self.initial_history
            self._set_state(self.initial_history_key, stored_initial_history)
        return stored_initial_history

    def _get_offsets(self) -> list[Union[None, int]]:
        return [None]
