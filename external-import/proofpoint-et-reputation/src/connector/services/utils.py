from datetime import datetime
from enum import Enum


class DateTimeFormat(Enum):
    DATETIME = "datetime"  # Object datetime
    ISO = "iso"  # Format ISO 8601
    TIMESTAMP = "timestamp"  # Timestamp Unix


class Utils:

    @staticmethod
    def get_now(now_format: DateTimeFormat = None):

        now = datetime.now()
        if now_format == DateTimeFormat.DATETIME:
            return now
        elif now_format == DateTimeFormat.ISO:
            return now.isoformat(sep=" ", timespec="seconds")
        elif now_format == DateTimeFormat.TIMESTAMP:
            return int(datetime.timestamp(now))
        else:
            now_isoformat = now.isoformat(sep=" ", timespec="seconds")
            now_timestamp = int(datetime.timestamp(now))
            return {
                "now_datetime": now,
                "now_isoformat": now_isoformat,
                "now_timestamp": now_timestamp,
            }
