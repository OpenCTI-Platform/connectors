import os
from datetime import datetime
from pathlib import Path

import yaml
from pycti import get_config_variable

from .custom_exceptions import ConnectorConfigurationError


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        if not os.path.isfile(config_file_path):
            return {}
        with open(config_file_path) as config_file:
            return yaml.load(config_file, Loader=yaml.FullLoader)

    def _initialize_configurations(self) -> None:
        """
        Extra configuration variables required for the connector
        to run.

        ALL S1 info is required and thus existence checks can
        halt execution. As well as this, the url, apitoken and
        the defined amount of attempts for an api call receive
        formatting in case of user input error.

        """

        # Ensure the presence of 'APIToken ' regardless of user config.
        configured_api_key = get_config_variable(
            "SENTINELONE_INCIDENTS_API_KEY",
            ["sentinelone_incidents", "api_key"],
            self.load,
        )
        if not configured_api_key:
            raise ConnectorConfigurationError(
                "SENTINELONE_INCIDENTS_API_KEY is not configured"
            )
        self.s1_api_key = (
            configured_api_key
            if "APIToken " in configured_api_key
            else f"APIToken {configured_api_key}"
        )

        configured_account_id = get_config_variable(
            "SENTINELONE_INCIDENTS_ACCOUNT_ID",
            ["sentinelone_incidents", "account_id"],
            self.load,
        )
        if not configured_account_id:
            raise ConnectorConfigurationError(
                "SENTINELONE_INCIDENTS_ACCOUNT_ID is not configured"
            )
        self.s1_account_id = configured_account_id

        # Ensure no slash at the end of the URL
        configured_url = get_config_variable(
            "SENTINELONE_INCIDENTS_URL", ["sentinelone_incidents", "url"], self.load
        )
        if not configured_url:
            raise ConnectorConfigurationError(
                "SENTINELONE_INCIDENTS_URL is not configured"
            )
        self.s1_url = configured_url.rstrip("/")

        # Ensure the maximum number of API attempts is a non-zero positive integer and default to 3 if not.
        configured_api_attempts = get_config_variable(
            "SENTINELONE_INCIDENTS_MAX_API_ATTEMPTS",
            ["sentinelone_incidents", "max_api_attempts"],
            self.load,
            isNumber=True,
            default=3,
        )
        if isinstance(configured_api_attempts, int) and configured_api_attempts > 0:
            self.max_api_attempts = configured_api_attempts
        else:
            self.max_api_attempts = 3

        configured_duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], self.load
        )
        if not configured_duration_period:
            raise ConnectorConfigurationError(
                "CONNECTOR_DURATION_PERIOD is not configured"
            )
        self.duration_period = configured_duration_period

        configured_import_start_date = get_config_variable(
            "SENTINELONE_INCIDENTS_IMPORT_START_DATE",
            ["sentinelone_incidents", "import_start_date"],
            self.load,
        )
        if not configured_import_start_date:
            raise ConnectorConfigurationError(
                "SENTINELONE_INCIDENTS_IMPORT_START_DATE is not configured"
            )
        # Validate the ISO-8601 shape at startup so a typo (or a
        # legacy ``YYYY-MM-DD`` value missing the time component) is
        # reported with a clear, contextual message instead of
        # surfacing later as a generic ``ValueError`` raised deep in
        # ``_parse_iso_datetime`` on the first scan cycle. The same
        # ``Z`` → ``+00:00`` normalisation applied by the runtime
        # parser is reproduced here so the sample value
        # ``2026-01-01T00:00:00Z`` is accepted on every supported
        # Python version (``datetime.fromisoformat`` only learned to
        # accept the trailing ``Z`` in 3.11).
        #
        # Beyond a plain ``datetime.fromisoformat`` check we also
        # require an explicit ``T`` separator and a non-empty time
        # component. ``datetime.fromisoformat("2026-01-01")`` is a
        # valid call (it returns midnight on that date), so without
        # the extra shape check a legacy ``YYYY-MM-DD`` value would
        # silently pass startup and then drift into ``midnight UTC``
        # at runtime — which is rarely what the operator wanted when
        # they pinned a precise import start point. The connector's
        # documented contract (``config.yml.sample`` /
        # ``docker-compose.yml`` / README all advertise
        # ``YYYY-MM-DDTHH:MM:SSZ``) is for a full datetime, so reject
        # date-only values up front with the same fail-fast,
        # contextual error that the parser-failure branch produces.
        normalised_start_date = configured_import_start_date.strip()
        if "T" not in normalised_start_date:
            raise ConnectorConfigurationError(
                f"SENTINELONE_INCIDENTS_IMPORT_START_DATE must be a full "
                f"ISO-8601 datetime with a time component (e.g. "
                f"'2026-01-01T00:00:00Z'), got "
                f"{configured_import_start_date!r}"
            )
        if normalised_start_date.endswith("Z"):
            normalised_start_date = normalised_start_date[:-1] + "+00:00"
        try:
            datetime.fromisoformat(normalised_start_date)
        except ValueError as exc:
            raise ConnectorConfigurationError(
                f"SENTINELONE_INCIDENTS_IMPORT_START_DATE is not a valid "
                f"ISO-8601 datetime (got {configured_import_start_date!r}): "
                f"{exc}"
            ) from exc
        self.import_start_date = configured_import_start_date
