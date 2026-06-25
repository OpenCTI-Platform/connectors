from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="c0f6a524-8f3e-4e5a-9b1c-7d2e6f4a8b0d",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ProofPoint ET Reputation",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr", "Domain-Name"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=24),
    )


class ProofpointEtReputationConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to
    the Proofpoint ET Reputation connector.
    """

    api_token: SecretStr = Field(
        description="API token for authentication with the ProofPoint ET Reputation API.",
    )
    create_indicator: bool = Field(
        description="Whether indicators should be created from the reputation data.",
        default=True,
    )
    min_score: int = Field(
        description="Minimum score threshold for processing reputation data (20-100).",
        default=20,
        ge=20,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig`
    and `ProofpointEtReputationConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    proofpoint_et_reputation: ProofpointEtReputationConfig = Field(
        default_factory=ProofpointEtReputationConfig
    )
