from .base import Verity471Stream


class Verity471SpotReportsStream(Verity471Stream):
    label = "spot_reports"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_spot_stream"
    size = 100
