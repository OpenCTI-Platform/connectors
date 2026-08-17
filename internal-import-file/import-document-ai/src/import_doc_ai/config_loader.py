"""
Configuration loader for the Import Document AI connector.

Historically this module parsed ``config.yml`` and environment variables via
``pycti.get_config_variable``. It now delegates configuration loading and
validation to the Pydantic ``ConnectorSettings`` model (manager-supported mode),
while keeping the same public ``ConfigConnector`` interface so the rest of the
connector code (``connector.py``, ``client_api.py``) remains unchanged.
"""

import base64

from .settings import ConnectorSettings


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector configuration from validated Pydantic settings.
        """

        # Load and validate configuration through the Pydantic settings model
        self.settings = ConnectorSettings()
        self._initialize_configurations()

    def to_helper_config(self) -> dict:
        """
        Return the configuration as a dict for ``pycti.OpenCTIConnectorHelper``.
        :return: Configuration dictionary
        """
        return self.settings.to_helper_config()

    def _initialize_configurations(self) -> None:
        """
        Expose connector extra parameters as flat attributes for backward
        compatibility with the rest of the connector code.
        :return: None
        """
        # Connector extra parameters

        import_document_ai = self.settings.import_document_ai

        self.api_base_url = import_document_ai.api_base_url

        self.api_key = (
            import_document_ai.api_key.get_secret_value()
            if import_document_ai.api_key
            else None
        )
        self.licence_key_base64 = (
            base64.b64encode(self.api_key.encode()) if self.api_key else None
        )

        # Read connector flags from config (create_indicator, include_relationships)
        self.create_indicator = import_document_ai.create_indicator

        self.include_relationships = import_document_ai.include_relationships
