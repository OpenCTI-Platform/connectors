"""Configuration loader for MISP Intel connector."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)

from .base_settings import ConfigBaseSettings
from .connector_configs import _ConfigLoaderConnector, _ConfigLoaderOCTI
from .misp_configs import _ConfigLoaderMisp, _ConfigLoaderProxy


class ConfigLoaderConnector(_ConfigLoaderConnector):
    """A concrete implementation of _ConfigLoaderConnector defining default connector configuration values."""

    id: str = Field(
        default="1c33c216-b24c-4839-b8bb-fdac2d769626",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="MISP Intel",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["misp"],
        description="The scope or type of data the connector is processing.",
    )
    live_stream_id: str = Field(
        default="live",
        alias="CONNECTOR_LIVE_STREAM_ID",
        description="The ID of the live stream to listen to.",
    )
    container_types: ListFromString = Field(
        default=["report", "grouping", "case-incident", "case-rfi", "case-rft"],
        alias="CONNECTOR_CONTAINER_TYPES",
        description="List of container types to process.",
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
    misp: _ConfigLoaderMisp = Field(
        default_factory=_ConfigLoaderMisp,
        description="MISP configurations.",
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
    ) -> tuple[PydanticBaseSettingsSource]:
        """Customize configuration sources to prioritize .env, then config.yml, then environment variables."""
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_file_encoding="utf-8",
                ),
            )
        elif yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )
        else:
            return (
                EnvSettingsSource(
                    settings_cls,
                ),
            )

    def model_dump_pycti(self) -> dict[str, Any]:
        """Export configuration in pycti-compatible format."""
        return self.model_dump(mode="json", context={"mode": "pycti"})

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
        if self.proxy.https and self.proxy.https.strip():
            os.environ["https_proxy"] = self.proxy.https
        if self.proxy.no_proxy and self.proxy.no_proxy.strip():
            os.environ["no_proxy"] = self.proxy.no_proxy
