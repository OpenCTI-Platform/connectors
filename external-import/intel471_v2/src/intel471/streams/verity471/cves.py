from typing import Union

from .base import Verity471Stream


class Verity471CVEsStream(Verity471Stream):
    label = "cves"
    group_label = "cves"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_vulnerability_stream"
    initial_history_key = "cves_initdate"

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"var_from": self._get_initial_history(), "size": 100}
        if cursor:
            kwargs["cursor"] = cursor
        return kwargs
