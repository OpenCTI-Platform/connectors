from .base import Verity471Stream


class Verity471BreachAlertsStream(Verity471Stream):
    label = "breach_alerts"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_breach_alert_stream"
    size = 100
