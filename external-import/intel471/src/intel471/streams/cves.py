from .common import Intel471Stream


class Intel471CVEsStream(Intel471Stream):
    ref = "cves"
    api_payload_objects_key = "cve_reports"
    api_class_name = "VulnerabilitiesApi"
    api_method_name = "cve_reports_get"

    def _get_api_kwargs(self, cursor):
        kwargs = {"_from": self.initial_history, "sort": "earliest", "count": 100}
        if cursor:
            kwargs["_from"] = cursor
        return kwargs

    def _get_cursor_value(self, api_response):
        return api_response.cve_reports[-1].activity.last + 1
