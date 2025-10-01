import os
from abc import ABC
from datetime import timedelta
from typing import Literal

import __main__
from connectors_sdk.core.pydantic import ListFromString
from connectors_sdk.models.configs import BaseConfigModel, _OpenCTIConfig
from pydantic import Field
from pydantic_settings import SettingsConfigDict

_MAIN_PATH = os.path.dirname(os.path.abspath(__main__.__file__))


class BaseConnectorConfig(BaseConfigModel, ABC):
    """
    Define config specific to a connector
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'."
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector."
    )
    log_level: Literal["debug", "info", "warn", "warning", "error", "critical"] = Field(
        description="The minimum level of logs to display."
    )
    # todo : type external import or internal enrichment


class BaseConnectorSettings(BaseConfigModel, ABC):
    """
    Interface for loading global configuration settings
    """

    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,
        description="OpenCTI configurations.",
    )
    connector: BaseConnectorConfig = Field(
        default_factory=BaseConnectorConfig,
        description="Connector configurations.",
    )

    # Setup model config and env vars parsing
    model_config = SettingsConfigDict(
        extra="allow",
        frozen=True,
        enable_decoding=False,
        env_nested_delimiter="_",
        env_nested_max_split=1,
        env_file=f"{_MAIN_PATH}/../.env",
        yaml_file=f"{_MAIN_PATH}/../config.yml",
    )
