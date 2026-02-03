from .base import Verity471Stream


class Verity471InfoReportsStream(Verity471Stream):
    label = "info_reports"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_info_stream"
    size = 10
