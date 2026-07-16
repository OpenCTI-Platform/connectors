from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="SocPrime",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["socprime"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class SocPrimeConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the SOC Prime connector.
    """

    api_key: SecretStr = Field(
        description="API key used to authenticate against the SOC Prime TDM API.",
    )
    content_list_name: ListFromString = Field(
        description="List of SOC Prime content list names to import rules from.",
        default=[],
    )
    job_ids: ListFromString = Field(
        description="List of SOC Prime job ids to import rules from.",
        default=[],
    )
    siem_type: ListFromString = Field(
        description="List of SIEM types to request rules for (used with job ids).",
        default=[],
    )
    indicator_siem_type: str = Field(
        description="SIEM type used to render rules imported from content lists.",
        default="sigma",
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to imported entities.",
            default="amber+strict",
        )
    )
    interval_sec: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda seconds: timedelta(seconds=int(seconds)),
    )

    @model_validator(mode="after")
    def check_dependencies(self):
        # At least one of content_list_name and job_ids must be set and non-empty
        if not self.content_list_name and not self.job_ids:
            raise ValueError(
                "Configuration error. At least one job id or one content list name must be provided."
            )

        # If content_list_name is set, indicator_siem_type must be set too (even if default='sigma')
        if self.content_list_name and not self.indicator_siem_type:
            raise ValueError(
                "'indicator_siem_type' must be provided when 'content_list_name' is set."
            )

        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `SocPrimeConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    socprime: SocPrimeConfig = Field(default_factory=SocPrimeConfig)
