from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="e30b0a45-93f3-44e3-93a7-4a2a8b2c5d9a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Zvelo",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["ipv4-addr", "ipv6-addr", "domain", "url", "indicator", "malware"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class ZveloConfig(BaseConfigModel):
    client_id: str = Field(description="Zvelo OAuth client ID.")
    client_secret: SecretStr = Field(description="Zvelo OAuth client secret.")
    collections: ListFromString = Field(
        description="Zvelo collections to ingest. Possible values: phish, malicious, threat.",
        default=["phish", "malicious", "threat"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    zvelo: ZveloConfig = Field(default_factory=ZveloConfig)
