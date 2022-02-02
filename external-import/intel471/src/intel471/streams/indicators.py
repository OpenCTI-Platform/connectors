from .common import Intel471Stream


class Intel471IndicatorsStream(Intel471Stream):

    ref = "indicators"
    api_payload_objects_key = "indicators"
    api_class_name = "IndicatorsApi"
    api_method_name = "indicators_stream_get"

    def _get_api_kwargs(self, cursor):
        kwargs = {"_from": self.initial_history, "count": 100}
        if cursor:
            kwargs["cursor"] = cursor
        return kwargs

    def _get_cursor_value(self, api_response):
        return api_response.cursor_next
