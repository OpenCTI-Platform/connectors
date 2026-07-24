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
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a7c557b2-4032-46ac-a956-5dc501257700",
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
        description=(
            "List of SOC Prime content list names to import rules from. At least "
            "one of `SOCPRIME_CONTENT_LIST_NAME` and `SOCPRIME_JOB_IDS` parameters "
            "has to be provided. If `SOCPRIME_CONTENT_LIST_NAME` is provided, then "
            "the parameter `SOCPRIME_INDICATOR_SIEM_TYPE` has to be provided too."
        ),
        default=[],
    )
    job_ids: ListFromString = Field(
        description=(
            "List of SOC Prime job ids to import rules from. At least one of "
            "`SOCPRIME_CONTENT_LIST_NAME` and `SOCPRIME_JOB_IDS` parameters has "
            "to be provided."
        ),
        default=[],
    )
    siem_type: ListFromString = Field(
        description="List of SIEM types to request rules for (used with job ids).",
        default=[],
    )
    indicator_siem_type: Literal[
        "sigma",
        "ala-rule",
        "ala",
        "elasticsearch",
        "es-eql",
        "xpack-watcher",
        "elasticsearch-rule",
        "es-rule-eql",
        "kibana",
        "elastalert",
        "qradar",
        "humio",
        "humio-alert",
        "splunk",
        "splunk_alert",
        "sumologic",
        "sumologic-cse",
        "sumologic-cse-rule",
        "arcsight-esm",
        "arcsight-keyword",
        "logpoint",
        "grep",
        "powershell",
        "graylog",
        "kafka",
        "rsa_netwitness",
        "carbonblack",
        "carbonblack-edr",
        "open-ioc",
        "fireeye-helix",
        "chronicle",
        "securonix",
        "s1-events",
        "s1-process",
        "mdatp",
        "qualys",
        "sysmon",
        "crowdstrike",
        "limacharlie",
        "devo",
        "snowflake",
        "athena",
        "opendistro-query",
        "opendistro-rule",
        "fortisiem",
        "axon-ads-query",
        "axon-ads-rule",
    ] = Field(
        description=(
            "SIEM type used to render rules imported from content lists. Only "
            "applicable to `SOCPRIME_CONTENT_LIST_NAME` parameter and not to "
            "`SOCPRIME_JOB_IDS`"
        ),
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
