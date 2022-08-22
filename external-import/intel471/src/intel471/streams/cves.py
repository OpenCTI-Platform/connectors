from typing import Union

from .common import Intel471Stream


class Intel471CVEsStream(Intel471Stream):
    label = "cves"
    api_payload_objects_key = "cve_reports"
    api_class_name = "VulnerabilitiesApi"
    api_method_name = "cve_reports_get"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"_from": self.initial_history, "sort": "earliest", "count": 100}
        if cursor:
            kwargs["_from"] = cursor
        return kwargs
