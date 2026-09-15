from settings import ConnectorSettings


class ConfigMalbeacon:
    def __init__(self):
        """
        Initialize the Malbeacon connector with necessary configurations
        """

        # Load and validate configuration through Pydantic settings
        self.settings = ConnectorSettings()
        self.load = self.settings.to_helper_config()
        self._initialize_configurations()

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """

        self.connector_scope = ",".join(self.settings.connector.scope)

        self.api_key = self.settings.malbeacon.api_key.get_secret_value()

        self.api_base_url = str(self.settings.malbeacon.api_base_url)

        self.indicator_score_level = self.settings.malbeacon.indicator_score_level

        self.max_tlp = self.settings.malbeacon.max_tlp
