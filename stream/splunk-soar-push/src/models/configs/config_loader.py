"""Configuration loader for Splunk SOAR Push connector."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)

from .base_settings import ConfigBaseSettings
from .connector_configs import _ConfigLoaderConnector, _ConfigLoaderOCTI
from .soar_configs import _ConfigLoaderProxy, _ConfigLoaderSoar


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="splunk-soar-push-connector",
        description="A unique identifier for this connector instance.",
    )
    name: str = Field(
        default="Splunk SOAR Push",
        description="Name of the connector.",
    )
    scope: str = Field(
        default="splunk-soar-push",
        description="The scope or type of data the connector is processing.",
    )
    live_stream_id: str = Field(
        default="ChangeMe",
        alias="CONNECTOR_LIVE_STREAM_ID",
        description="The ID of the live stream to listen to.",
    )


class ConfigLoader(ConfigBaseSettings):
    """Interface for loading global configuration settings."""

    opencti: _ConfigLoaderOCTI = Field(
        default_factory=_ConfigLoaderOCTI,
        description="OpenCTI configurations.",
    )
    connector: ConfigLoaderConnector = Field(
        default_factory=ConfigLoaderConnector,
        description="Connector configurations.",
    )
    splunk_soar: _ConfigLoaderSoar = Field(
        default_factory=_ConfigLoaderSoar,
        description="Splunk SOAR configurations.",
        alias="splunk_soar",
    )
    proxy: _ConfigLoaderProxy = Field(
        default_factory=_ConfigLoaderProxy,
        description="Proxy configurations.",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Customize configuration sources to prioritize config.yml, then environment variables."""
        # Look for config.yml in the src directory (2 levels up from configs/)
        yaml_path = Path(__file__).parents[2] / "config.yml"

        if yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
                EnvSettingsSource(
                    settings_cls,
                ),
            )
        else:
            # Fall back to environment variables only
            return (
                EnvSettingsSource(
                    settings_cls,
                ),
            )

    def model_dump_pycti(self) -> dict[str, Any]:
        """Export configuration in pycti-compatible format."""
        # OpenCTIConnectorHelper's get_config_variable expects a nested structure
        return {
            "opencti": {
                "url": str(self.opencti.url),
                "token": self.opencti.token.get_secret_value(),
            },
            "connector": {
                "id": self.connector.id,
                "type": self.connector.type,
                "name": self.connector.name,
                "scope": self.connector.scope,
                "confidence_level": self.connector.confidence_level,
                "log_level": self.connector.log_level,
                "live_stream_id": self.connector.live_stream_id,
                "live_stream_listen_delete": self.connector.live_stream_listen_delete,
                "live_stream_no_dependencies": self.connector.live_stream_no_dependencies,
            },
        }

    def get_proxy_settings(self) -> Optional[Dict[str, Any]]:
        """
        Get proxy settings for requests.

        :return: Dictionary with proxy settings or None if no proxies configured
        """
        proxies = {}

        if self.proxy.http and self.proxy.http.strip():
            proxies["http"] = self.proxy.http
        if self.proxy.https and self.proxy.https.strip():
            proxies["https"] = self.proxy.https

        return proxies if proxies else None

    def setup_proxy_env(self) -> None:
        """Set up proxy environment variables if configured."""
        if self.proxy.http and self.proxy.http.strip():
            os.environ["http_proxy"] = self.proxy.http
            os.environ["HTTP_PROXY"] = self.proxy.http
        if self.proxy.https and self.proxy.https.strip():
            os.environ["https_proxy"] = self.proxy.https
            os.environ["HTTPS_PROXY"] = self.proxy.https
        if self.proxy.no_proxy and self.proxy.no_proxy.strip():
            os.environ["no_proxy"] = self.proxy.no_proxy
            os.environ["NO_PROXY"] = self.proxy.no_proxy
