from typing import Any, Union

from .common import Intel471Stream


class Intel471ReportsStream(Intel471Stream):
    label = "reports"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "reports_get"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {
            "last_updated_from": self.initial_history,
            "sort": "earliest",
            "count": 100,
        }
        if cursor:
            kwargs["last_updated_from"] = cursor
        return kwargs

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return str(
            getattr(api_response, self.api_payload_objects_key)[-1].last_updated + 1
        )
