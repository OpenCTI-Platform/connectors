import re
from datetime import datetime, timezone
from enum import Enum


class DateTimeFormat(Enum):
    DATETIME = "datetime"  # Object datetime
    ISO = "iso"  # Format ISO 8601
    TIMESTAMP = "timestamp"  #  Unix Timestamp


class Utils:

    @staticmethod
    def get_now(now_format: DateTimeFormat = None) -> datetime | str | int | dict:
        """
        Utility method: Get the current date and time in various formats.

        Parameters:
            now_format (DateTimeFormat, None) :
            The desired format for the current date and time. Possible values are:
            - DateTimeFormat.DATETIME: Return a `datetime` (UTC) object representing the current date and time.
            - DateTimeFormat.ISO: Return the current date and time as an ISO 8601 (UTC) formatted string.
            - DateTimeFormat.TIMESTAMP: Return the current time as a UNIX timestamp (seconds since epoch).
            - None (default): If no format is specified, returns a dictionary containing all the formats.

        Returns:
            datetime, str, int, or dict :
            - If `now_format` is DateTimeFormat.DATETIME, return a `datetime` (UTC) object.
            - If `now_format` is DateTimeFormat.ISO, return an ISO 8601 (UTC) formatted string.
            - If `now_format` is DateTimeFormat.TIMESTAMP, return an integer UNIX Timestamp.
            - If `now_format` is None (default), returns a dictionary with the following keys:
                - "now_datetime": The current `datetime` (UTC) object.
                - "now_isoformat": The current date and time as an ISO 8601 (UTC) formatted string.
                - "now_timestamp": The current time as a UNIX Timestamp.

        Examples:
            >> get_now(DateTimeFormat.DATETIME) = datetime.datetime(2025, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)

            >> get_now(DateTimeFormat.ISO) = '2025-01-01T00:00:00+00:00'

            >> get_now(DateTimeFormat.TIMESTAMP) = 1735689600

            >> get_now() =
            {
                "current_utc_datetime": datetime.datetime(2025, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc),
                "current_utc_isoformat": "2025-01-01T00:00:00+00:00",
                "current_timestamp": 1735689600,
            }
        """
        now_utc = datetime.now(timezone.utc)
        if now_format == DateTimeFormat.DATETIME:
            return now_utc
        elif now_format == DateTimeFormat.ISO:
            return now_utc.isoformat(timespec="seconds")
        elif now_format == DateTimeFormat.TIMESTAMP:
            return int(datetime.timestamp(now_utc))
        else:
            return {
                "current_utc_datetime": now_utc,
                "current_utc_isoformat": now_utc.isoformat(timespec="seconds"),
                "current_timestamp": int(datetime.timestamp(now_utc)),
            }

    @staticmethod
    def transform_description_to_markdown(report_info: dict) -> str:
        description_field_in_opencti = ""
        markdown_table = ""
        markdown_init = "\n| Additional Information | Value |\n|-------|-------|\n"
        markdown_adding_line = ""

        fields_to_render = [
            ("Threat Title", report_info.get("threat_title")),
            ("Executive Summary", report_info.get("description")),
            ("First Published ('US/Eastern')", report_info.get("first_published")),
            ("Last Updated ('US/Eastern')", report_info.get("last_published")),
            ("Language", report_info.get("language") or "N/A"),
            ("Brands", report_info.get("brands") or "N/A"),
            ("Recipient NAICS Subsector(s)", report_info.get("sub_sector") or "N/A"),
            ("SEG Data", report_info.get("seg_data") or "N/A"),
        ]

        for additional_information, value in fields_to_render:
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "N/A"
            elif not value:
                value = "N/A"

            # Remove all unwanted elements
            clean_value = re.sub(r"[|\n\r]", " ", str(value)).strip()

            markdown_adding_line += f"| {additional_information} | {clean_value} |\n"

        if markdown_adding_line:
            markdown_table += markdown_init
            markdown_table += markdown_adding_line

        description_field_in_opencti += markdown_table
        return description_field_in_opencti
