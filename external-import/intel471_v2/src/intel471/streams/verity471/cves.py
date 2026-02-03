from typing import Any, Union

from .base import Verity471Stream


class Intel471CVEsStream(Verity471Stream):
    label = "cves"
    group_label = "cves"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_vulnerability_stream"
    initial_history_key = "cves_initdate"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"var_from": self.initial_history, "size": 100}
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
