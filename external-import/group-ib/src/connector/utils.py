from datetime import timedelta

from connector.settings import ConfigConnector
from isodate import parse_duration
from pycti import OpenCTIConnectorHelper


class ExternalImportHelper:
    @staticmethod
    def validation_interval(
        cfg: ConfigConnector, helper: OpenCTIConnectorHelper
    ) -> str:
        interval = cfg.connector_duration_period
        helper.connector_logger.info(
            f"Verifying integrity of the CONNECTOR_DURATION_PERIOD value: '{interval}'"
        )
        try:
            duration = parse_duration(interval)
            if not isinstance(duration, timedelta):
                raise ValueError("Parsed duration is not a valid timedelta object.")
            return interval
        except Exception as ex:
            msg = (
                f"Error ({ex}) when grabbing CONNECTOR_DURATION_PERIOD environment variable: "
                f"'{interval}'. It SHOULD be a valid ISO-8601 duration string "
                "(e.g., 'P7D', 'PT12H', 'PT10M', 'PT30S')."
            )
            helper.connector_logger.error(msg)
            raise ValueError(msg) from ex

    @staticmethod
    def validation_update_existing_data(
        cfg: ConfigConnector, helper: OpenCTIConnectorHelper
    ) -> bool:
        raw = cfg.connector_update_existing_data
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str) and raw.lower() in ("true", "false"):
            return raw.lower() == "true"

        helper.connector_logger.warning(
            f"Invalid CONNECTOR_UPDATE_EXISTING_DATA value: {raw!r}. "
            "Expected 'true' or 'false'. Falling back to False."
        )
        return False
