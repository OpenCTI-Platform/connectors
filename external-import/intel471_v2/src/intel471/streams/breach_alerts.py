from typing import Any, Union

from .common import Intel471Stream


class Intel471BreachAlertsStream(Intel471Stream):
    label = "breach_alerts"
    group_label = "reports"
    api_payload_objects_key = "breach_alerts"
    api_class_name = "ReportsApi"
    api_method_name = "breach_alerts_get"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {
            "breach_alert": "*",
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
