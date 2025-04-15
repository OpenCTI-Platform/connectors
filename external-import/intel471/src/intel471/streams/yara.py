from typing import Union

from .common import Intel471Stream


class Intel471YARAStream(Intel471Stream):
    label = "yara"
    api_payload_objects_key = "yaras"
    api_class_name = "YARAApi"
    api_method_name = "yara_get"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {
            "_from": self.initial_history,
            "yara": "*",
            "sort": "earliest",
            "count": 100,
        }
        if cursor:
            kwargs["_from"] = cursor
        return kwargs
