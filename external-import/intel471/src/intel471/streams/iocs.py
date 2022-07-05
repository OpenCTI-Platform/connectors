from typing import Union, Any

from .common import Intel471Stream


class Intel471IOCsStream(Intel471Stream):
    label = "iocs"
    api_payload_objects_key = "iocs"
    api_class_name = "IOCsApi"
    api_method_name = "iocs_get"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {
            "_from": self.initial_history,
            "ioc": "*",
            "sort": "earliest",
            "count": 100,
        }
        if cursor:
            kwargs["_from"] = cursor
        return kwargs

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return str(
            getattr(api_response, self.api_payload_objects_key)[-1].last_updated + 1
        )
