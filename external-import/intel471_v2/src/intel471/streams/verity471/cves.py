from .base import Verity471Stream


class Verity471CVEsStream(Verity471Stream):
    label = "cves"
    group_label = "cves"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_vulnerability_stream"
    size = 100
