from pydantic import ValidationError
from src.connector.models import ConfigLoader


class ServiceNowConfig:
    def __init__(self):
        """Initialize the connector with necessary configurations"""
        self.load = self._load_config()

    @staticmethod
    def _load_config() -> ConfigLoader:
        """Load the application configuration using Pydantic Settings.

        The configuration is loaded from a single source, following a specific order:
        1. .env file (DotEnvSettingsSource) → If present, it is used as the primary configuration source.
        2. config.yml file (YamlConfigSettingsSource) → If the .env file is missing, the YAML configuration is used instead.
        3. System environment variables (EnvSettingsSource) → If neither a '.env' nor a 'config.yml' file is found,
           the system environment variables are used as the last fallback.

        It validates the configuration using Models Pydantic and ensures that only valid settings are returned.

        Returns:
            ConfigLoader: A model containing the validated configuration.
        """
        try:

            load_settings = ConfigLoader()
            return load_settings

        except ValidationError as err:
            raise ValueError(err)

        except Exception as err:
            raise ValueError(err)
