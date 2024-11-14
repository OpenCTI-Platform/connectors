#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
from datetime import datetime, timedelta

from pydantic import TypeAdapter


class ConnectorUtils:
    def __init__(self, helper, config):
        self.helper = helper
        self.config = config

    def convert_to_duration_period(self) -> str:
        """
        Converts an ISO 8601 duration period to a formatted datetime string (yyyy-MM-dd HH:mm:ss).

        This method takes an ISO 8601 duration string (e.g., "P5D" for 5 days), converts it into
        a timedelta, subtracts it from the current date and time, and returns the resulting date
        and time in the format 'yyyy-MM-dd HH:mm:ss'. This formatted datetime is used as the
        start date in the API request to PassiveTotal.

        "import_last_seen_time_window" a string representing the ISO 8601 duration (e.g., 'P5D', 'P2H').
        Defaults to "P30D" (30 days) if not specified, which represents a period of 30 days.
        The duration should be provided in the format "PnYnMnDTnHnMnS" (e.g., "P5D" for 5 days).

        Example:
            "P5D" -> 5 days before the current date in "yyyy-MM-dd HH:mm:ss" format.

        :return: A formatted date-time string (yyyy-MM-dd HH:mm:ss) representing the date and time
                 that corresponds to the duration subtracted from the current date and time.
        """
        try:
            timedelta_adapter = TypeAdapter(timedelta)
            td = timedelta_adapter.validate_python(
                self.config.import_last_seen_time_window
            )
            duration_period_in_seconds = int(td.total_seconds())

            new_date = datetime.now() - timedelta(seconds=duration_period_in_seconds)
            formatted_date_iso_format = new_date.strftime("%Y-%m-%d %H:%M:%S")
            return formatted_date_iso_format

        except Exception as e:
            self.helper.connector_logger.error(
                "An error occurred during the conversion of the duration period",
                {"error": str(e)},
            )
