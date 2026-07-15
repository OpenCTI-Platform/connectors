from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="c17be91c-4879-4f17-8091-6fd8ad2b99ab",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RstThreatFeed",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class RstThreatFeedConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RstThreatFeedConnector`.
    """

    baseurl: str = Field(
        description="RST Threat Feed Base URL. By default, use https://api.rstcloud.net/v1. In some cases, you may want to use a local API endpoint.",
        default="https://api.rstcloud.net/v1",
    )
    apikey: SecretStr = Field(
        description="Your API Key for accessing RST Cloud.",
    )
    ssl_verify: bool = Field(
        description="If set to false, SSL verification is disabled (use with caution, sometimes needed when SSL inspection is enabled).",
        default=True,
    )
    contimeout: int = Field(
        description="Connection timeout (seconds) to the RST Threat Feed API.",
        default=30,
    )
    readtimeout: int = Field(
        description="Read timeout (seconds) for each feed download (API redirects to AWS S3).",
        default=120,
    )
    retry: int = Field(
        description="Number of attempts to download the feed.",
        default=2,
    )
    interval: int = Field(
        description="Fetch interval in seconds (how often the connector will run for the feed download).",
        default=86400,
    )
    max_retries: int = Field(
        description="Maximum number of retry attempts for connection issues when sending the STIX bundle to OpenCTI.",
        default=3,
    )
    retry_delay: int = Field(
        description="Initial delay in seconds before retrying a failed connection to OpenCTI.",
        default=10,
    )
    retry_backoff_multiplier: float = Field(
        description="Multiplier applied to the retry delay for exponential backoff between retries to send data to OpenCTI.",
        default=2.0,
    )
    min_score_import: int = Field(
        description="Import only indicators with risk score more than this value.",
        default=20,
    )
    latest: str = Field(
        description="Defines how often the latest threat feed data is fetched. Options: 1h, 4h, 12h, day.",
        default="day",
    )
    ip: bool = Field(
        description="If true, the connector retrieves threat intelligence data for IP addresses.",
        default=True,
    )
    domain: bool = Field(
        description="If true, the connector retrieves threat intelligence data for domains.",
        default=True,
    )
    url: bool = Field(
        description="If true, the connector retrieves threat intelligence data for URLs.",
        default=True,
    )
    hash: bool = Field(
        description="If true, the connector retrieves threat intelligence data for file hashes (MD5, SHA1, SHA256).",
        default=True,
    )
    min_score_detection_ip: int = Field(
        description="IP indicators with risk score more than this value are marked with x_opencti_detection=true.",
        default=45,
    )
    min_score_detection_domain: int = Field(
        description="Domain indicators with risk score more than this value are marked with x_opencti_detection=true.",
        default=45,
    )
    min_score_detection_url: int = Field(
        description="URL indicators with risk score more than this value are marked with x_opencti_detection=true.",
        default=45,
    )
    min_score_detection_hash: int = Field(
        description="Hash indicators with risk score more than this value are marked with x_opencti_detection=true.",
        default=45,
    )
    only_new: bool = Field(
        description='If true, import only indicators with recent "First Seen" (do not re-import older indicators based on "Last Seen").',
        default=True,
    )
    only_attributed: bool = Field(
        description="If true, import only indicators that are attributed to known threats.",
        default=False,
    )
    keep_named_vulns: bool = Field(
        description="If true, create named vulnerabilities as separate objects, otherwise prefer CVE numbers.",
        default=True,
    )
    create_mitre_ttp: Optional[bool] = DeprecatedField(
        default=None,
        description="(Deprecated) Use create_mitre_ttps instead. Kept for backward compatibility.",
        deprecated="Use 'create_mitre_ttps' instead.",
        new_namespaced_var="create_mitre_ttps",
    )
    create_custom_ttps: bool = Field(
        description="If true, create custom attack-pattern objects for named techniques/attacks not present in MITRE ATT&CK.",
        default=True,
    )
    create_mitre_ttps: bool = Field(
        description="If true, create relationships: Indicator -> indicates -> Attack-Pattern (MITRE TTP). Will create many relationships, use with caution.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RstThreatFeedConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    rst_threat_feed: RstThreatFeedConfig = Field(default_factory=RstThreatFeedConfig)
