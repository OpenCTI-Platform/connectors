from datetime import timedelta

from .settings import ConnectorSettings


class ConfigConnector:
    def __init__(self, settings: ConnectorSettings | None = None):
        """
        Initialize the connector with necessary configurations.

        Configuration is loaded and validated through the Pydantic
        ``ConnectorSettings`` model. Values consumed by the rest of the connector
        are exposed under their historical names below, so no downstream code
        needs to change.
        """
        self.settings = settings or ConnectorSettings()
        self._initialize_configurations()

    def to_helper_config(self) -> dict:
        """Return a config dict suitable for ``pycti.OpenCTIConnectorHelper``."""
        return self.settings.to_helper_config()

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period: timedelta = self.settings.connector.duration_period

        # Connector extra parameters
        self.api_base_url: str = self.settings.catalyst.base_url

        self.api_key: str | None = (
            self.settings.catalyst.api_key.get_secret_value()
            if self.settings.catalyst.api_key is not None
            else None
        )

        self.tlp_level: str = self.settings.catalyst.tlp_level

        self.tlp_filter: str | None = self.settings.catalyst.tlp_filter

        self.category_filter: str | None = self.settings.catalyst.category_filter

        self.sync_days_back: int = self.settings.catalyst.sync_days_back

        self.create_observables: bool = self.settings.catalyst.create_observables

        self.create_indicators: bool = self.settings.catalyst.create_indicators
