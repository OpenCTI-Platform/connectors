import logging

from settings import ConnectorSettings

logger = logging.getLogger(__name__)


class ConfigVariables:
    """
    Configuration loader for WhoisFreaks OpenCTI Connector.
    Reads settings via the connectors-sdk (config.yml or environment variables).
    """

    def __init__(self) -> None:
        self._settings = ConnectorSettings()

        # Generic OpenCTI connection fields (passed through to helper)
        self.opencti_url: str = self._settings.opencti.url
        self.opencti_token: str = self._settings.opencti.token

        # Connector meta-fields
        self.connector_id: str = self._settings.connector.id
        self.connector_type: str = self._settings.connector.type
        self.connector_name: str = self._settings.connector.name
        self.connector_scope: str = self._settings.connector.scope
        self.connector_auto: bool = self._settings.connector.auto
        self.connector_log_level: str = self._settings.connector.log_level.upper()

        # WhoisFreaks-specific fields
        self.whoisfreaks_api_key: str = (
            self._settings.whoisfreaks.api_key.get_secret_value()
        )
        self.tlp_level: str = self._settings.whoisfreaks.tlp_level

        logger.debug("[WhoisFreaks] Configuration loaded successfully.")

    def to_helper_config(self) -> dict:
        """Return the dict expected by OpenCTIConnectorHelper."""
        return self._settings.to_helper_config()
