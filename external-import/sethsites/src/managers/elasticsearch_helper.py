from datetime import datetime
from elasticsearch_dsl import Search


class ElasticsearchHelper:
    @staticmethod
    def set_time_range(s: Search, field, start: datetime = None, end: datetime = None):
        start_time = None
        end_time = None
        if start:
            start_time = start.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if end:
            end_time = end.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if start and end:
            s = s.filter("range", **{field: {'gte': start_time, 'lte': end_time,
                                             'format': 'strict_date_optional_time_nanos'}})
        elif start:
            s = s.filter("range", **{field: {'gte': start_time, 'format': 'strict_date_optional_time_nanos'}})
        elif end:
            s = s.filter("range", **{field: {'lte': end_time, 'format': 'strict_date_optional_time_nanos'}})
        return s
