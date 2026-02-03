from .base import Verity471Stream


class Verity471FintelStream(Verity471Stream):
    label = "fintel"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_fintel_stream"
    initial_history_key = "fintel_initdate"
    size = 10
