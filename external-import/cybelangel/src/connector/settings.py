from datetime import timedelta
from typing import Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Override `BaseExternalImportConnectorConfig` to add defaults for CybelAngel."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ChangeMe",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CybelAngel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=6),
    )


class CybelAngelConfig(BaseConfigModel):
    """Configuration fields specific to the CybelAngel connector."""

    client_id: str = Field(
        description="CybelAngel OAuth2 client ID.",
    )
    client_secret: SecretStr = Field(
        description="CybelAngel OAuth2 client secret.",
    )
    api_url: str = Field(
        description="CybelAngel platform API base URL.",
        default="https://platform.cybelangel.com",
    )
    auth_url: str = Field(
        description="CybelAngel OAuth2 token endpoint URL.",
        default="https://auth.cybelangel.com/oauth/token",
    )
    audience: Optional[str] = Field(
        description=(
            "OAuth2 audience claim. Defaults to api_url with a trailing slash when not set."
        ),
        default=None,
    )
    marking: str = Field(
        description=(
            "TLP marking to apply to imported objects. "
            "Accepted values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED."
        ),
        default="TLP:AMBER+STRICT",
    )
    fetch_period: str = Field(
        description=(
            "Number of days to look back on the first run. "
            'Use "all" to fetch all available data.'
        ),
        default="7",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Root settings for the CybelAngel connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    cybelangel: CybelAngelConfig = Field(default_factory=CybelAngelConfig)
