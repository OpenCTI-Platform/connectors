import os
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def prepare_iso_format(date: str | None) -> str:
        """
        Converts a date string to ISO 8601 format with UTC timezone. If the input date is empty, `None`,
        or invalid, a default date of "2020-01-01T00:00:00Z" is returned.

        :param date: The date string to be formatted, expected in ISO 8601 format. Can be empty or `None`.
        :return: The formatted date string in ISO 8601 format with 'Z' as the timezone indicator if valid.
                 Returns "2020-01-01T00:00:00Z" if `date` is invalid, empty, or `None`.
        """
        try:
            if date is not None and date.strip():
                iso_datetime = datetime.fromisoformat(date).replace(tzinfo=timezone.utc)
                prepared_date = iso_datetime.isoformat()
            else:
                default_date = "2020-01-01T00:00:00Z"
                return default_date
            return prepared_date
        except ValueError:
            default_date = "2020-01-01T00:00:00Z"
            return default_date

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.tenant_id = get_config_variable(
            "MICROSOFT_DEFENDER_INCIDENTS_TENANT_ID",
            ["microsoft_defender_incidents", "tenant_id"],
            self.load,
        )
        self.client_id = get_config_variable(
            "MICROSOFT_DEFENDER_INCIDENTS_CLIENT_ID",
            ["microsoft_defender_incidents", "client_id"],
            self.load,
        )
        self.client_secret = get_config_variable(
            "MICROSOFT_DEFENDER_INCIDENTS_CLIENT_SECRET",
            ["microsoft_defender_incidents", "client_secret"],
            self.load,
        )
        self.api_base_url = get_config_variable(
            "MICROSOFT_DEFENDER_INCIDENTS_API_BASE_URL",
            ["microsoft_defender_incidents", "api_base_url"],
            self.load,
            default="https://graph.microsoft.com/v1.0",
        )
        self.incident_path = get_config_variable(
            "MICROSOFT_DEFENDER_INCIDENTS_INCIDENT_PATH",
            ["microsoft_defender_incidents", "incident_path"],
            self.load,
            default="/security/incidents",
        )
        microsoft_defender_import_start_date_var = get_config_variable(
            "MICROSOFT_DEFENDER_INCIDENTS_IMPORT_START_DATE",
            ["microsoft_defender_incidents", "import_start_date"],
            self.load,
        )
        self.import_start_date = self.prepare_iso_format(
            microsoft_defender_import_start_date_var
        )
