from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="FortiSIEM Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'.",
        default=["fortisiem"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=15),
    )


class FortiSIEMIncidentsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the FortiSIEM Incidents connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the FortiSIEM Supervisor (e.g. https://fortisiem.example.com).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    organization: str = Field(
        description="FortiSIEM organization used to scope the REST API user (e.g. 'super').",
        default="super",
    )
    username: str = Field(
        description="FortiSIEM REST API user name.",
    )
    password: SecretStr = Field(
        description="FortiSIEM REST API user password.",
    )
    import_window_days: int = Field(
        description="Number of days of incidents to import on the first run.",
        default=7,
        ge=1,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to the imported incidents.",
            default="amber",
        )
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the FortiSIEM Supervisor.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `FortiSIEMIncidentsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    fortisiem_incidents: FortiSIEMIncidentsConfig = Field(
        default_factory=FortiSIEMIncidentsConfig
    )
