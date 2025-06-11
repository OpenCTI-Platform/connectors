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
    def transform_description_to_markdown(
        comment_to_exclude: list[str], description: str, comments: str
    ) -> str:
        """This method allows you to structure the entity's description in OpenCTI, starting with a description and then
        adding a Markdown table to list the comments written in ServiceNow. The description field can be empty, just
        like the Markdown table.

        The function divides comments into blocks based on a pattern that detects date and time (each comment starts
        with a date and time). Depending on the user's configuration, comments can be filtered.
        Removal of unwanted elements (e.g. code tags, HTML tags, line breaks and unwanted pipes).

        Args:
            comment_to_exclude (list[str]): A list of comment types to exclude (e.g., ["private", "auto"]).
            description (str): The original description content to include at the top.
            comments (str): The raw comment string from ServiceNow to parse and format.

        Returns:
            str: A formatted string containing the description and comments in the form of a Markdown table.
        """
        pattern = r"(?=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - )"
        blocks = re.split(pattern, comments.strip())
        list_comments = [block.strip() for block in blocks if block.strip()]

        description_field_in_opencti = description + "\n"

        if comments:
            markdown_table = ""
            markdown_init = (
                "\n| Date | Author | Comments and Work Notes |\n| --- | --- | --- |\n"
            )
            markdown_adding_line = ""
            for comment in list_comments:
                match = re.match(r"^(.*?) - (.*?)\n(.*)", comment, re.DOTALL)
                if match:
                    date = match.group(1).strip()  # Ex: "2025-04-22 22:58:30"
                    author = match.group(
                        2
                    ).strip()  # Ex: "System (Automation activity)"
                    message = match.group(
                        3
                    ).strip()  # Ex: "Risk score changed from Empty to 69 due to change..."

                    # Three types of possible exclusions :
                    comment_mapping = {
                        "private": "work notes",
                        "public": "additional comments",
                        "auto": "automation activity",
                    }
                    # Detection and filtering comments according to configuration.
                    list_comment_to_exclude_config = comment_to_exclude or []
                    if any(
                        comment_mapping[item.lower()] in author.lower()
                        for item in list_comment_to_exclude_config
                    ):
                        continue

                    # Remove all unwanted elements
                    message = re.sub(r"\[/?code]", "", message)
                    message = re.sub(r"<.*?>", "", message)
                    message = re.sub(r"\|", " ", message)
                    message = re.sub(r"\n", " ", message)

                    markdown_adding_line += f"| {date} | {author} | {message} |\n"

            if markdown_adding_line:
                markdown_table += markdown_init
                markdown_table += markdown_adding_line

            description_field_in_opencti += markdown_table
        return description_field_in_opencti
