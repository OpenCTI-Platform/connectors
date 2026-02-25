from .base import Verity471Stream


class Verity471IndicatorsStream(Verity471Stream):
    label = "indicators"
    group_label = "indicators"
    api_payload_objects_key = "indicators"
    api_class_name = "IndicatorsApi"
    api_method_name = "get_indicators_stream"
    size = 100
