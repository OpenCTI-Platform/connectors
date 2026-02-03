from .base import Verity471Stream


class Verity471GeopolReportsStream(Verity471Stream):
    label = "geopol_reports"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_geopol_stream"
    size = 100
