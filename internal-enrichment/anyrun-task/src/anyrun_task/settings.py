from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, SkipValidation


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
        default="ANY.RUN task",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Artifact", "Url"],
    )


class AnyrunTaskConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AnyrunTaskConnector`.
    """

    token: SecretStr = Field(
        description="ANY.RUN API token for authentication.",
    )
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(description="Maximum TLP level for the connector.", default="TLP:AMBER")
    url: HttpUrl = Field(
        description="Base URL for the ANY.RUN API.",
        default=HttpUrl("https://api.any.run"),
    )
    task_timer: int = Field(
        description="Sandbox execution time in seconds.", default=60
    )
    os: str = Field(
        description="Operating system for sandbox environment.", default="windows"
    )
    bitness: SkipValidation[str] = DeprecatedField(  # type: ignore[assignment]
        deprecated="Deprecated: Use `os_bitness` instead.",
        new_namespaced_var="os_bitness",
    )
    os_bitness: Literal["32", "64"] = Field(
        description="Operating system bitness: `32` or `64`.", default="64"
    )
    version: SkipValidation[str] = DeprecatedField(  # type: ignore[assignment]
        deprecated="Deprecated: Use `os_version` instead.",
        new_namespaced_var="os_version",
    )
    os_version: Literal["7", "8.1", "10", "11"] = Field(
        description="Windows version: `7`, `8.1`, `10`, or `11`.", default="10"
    )
    locale: SkipValidation[str] = DeprecatedField(  # type: ignore[assignment]
        deprecated="Deprecated: Use `os_locale` instead.",
        new_namespaced_var="os_locale",
    )
    os_locale: str = Field(
        description="Operating system language locale.", default="en-US"
    )
    browser: SkipValidation[str] = DeprecatedField(  # type: ignore[assignment]
        deprecated="Deprecated: Use `os_browser` instead.",
        new_namespaced_var="os_browser",
    )
    os_browser: Literal[
        "Google Chrome",
        "Mozilla Firefox",
        "Opera",
        "Internet Explorer",
        "Microsoft Edge",
    ] = Field(
        description=(
            "Browser for URL analysis: `Google Chrome`, `Mozilla Firefox`, `Opera`, "
            "`Internet Explorer`, `Microsoft Edge`."
        ),
        default="Google Chrome",
    )
    privacy: Literal["public", "bylink", "owner", "team"] = Field(
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


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `AnyrunTaskConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    anyrun: AnyrunTaskConfig = Field(default_factory=AnyrunTaskConfig)
