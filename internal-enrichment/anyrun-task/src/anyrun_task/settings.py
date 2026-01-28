from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="30c40257-9514-4b54-bcc9-15445fe21e5e",
    )
    name: str = Field(
        description="The name of the connector.",
        default="AnyrunTask",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class AnyrunTaskConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AnyrunTaskConnector`.
    """

    token: SecretStr = Field(
        description="ANY.RUN API token for authentication.",
        default=SecretStr("ChangeMe"),
    )
    max_tlp: str = Field(
        description="Maximum TLP level for the connector.", default="TLP:AMBER"
    )
    url: str = Field(
        description="Base URL for the ANY.RUN API.", default="https://api.any.run"
    )
    task_timer: int = Field(
        description="Sandbox execution time in seconds.", default=60
    )
    os: str = Field(
        description="Operating system for sandbox environment.", default="windows"
    )
    bitness: str = Field(
        description="Operating system bitness: `32` or `64`.", default="64"
    )
    version: str = Field(
        description="Windows version: `7`, `8.1`, `10`, or `11`.", default="10"
    )
    os_locale: str = Field(
        description="Operating system language locale.", default="en-US"
    )
    browser: str = Field(
        description="Browser for URL analysis: `Google Chrome`, `Mozilla Firefox`, `Opera`, `Internet Explorer`, `Microsoft Edge`.",
        default="Google Chrome",
    )
    privacy: str = Field(
        description="Task privacy: `public`, `bylink`, `owner`, `team`.",
        default="bylink",
    )
    automated_interactivity: bool = Field(
        description="Enable ML-based automated interactivity during analysis.",
        default=False,
    )
    ioc: bool = Field(
        description="Import IOCs (domains, URLs, IPs) extracted during analysis.",
        default=True,
    )
    mitre: bool = Field(
        description="Create relationships to MITRE ATT&CK techniques.", default=False
    )
    processes: bool = Field(
        description="Import malicious process observables.", default=False
    )
    task_timer: str = Field(
        description="Sandbox execution time in seconds.", default="60", deprecated=True
    )
    os_bitness: str = Field(
        description="Operating system bitness: `32` or `64`.",
        default="64",
        deprecated=True,
    )
    os_version: str = Field(
        description="Windows version: `7`, `8.1`, `10`, or `11`.",
        default="10",
        deprecated=True,
    )
    os_locale: str = Field(
        description="Operating system language locale.",
        default="en-US",
        deprecated=True,
    )
    os_browser: str = Field(
        description="Browser for URL analysis: `Google Chrome`, `Mozilla Firefox`, `Opera`, `Internet Explorer`, `Microsoft Edge`.",
        default="Google Chrome",
        deprecated=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `AnyrunTaskConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    anyrun: AnyrunTaskConfig = Field(default_factory=AnyrunTaskConfig)
