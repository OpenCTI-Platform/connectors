"""
USTA connector settings.

Configuration management using Pydantic models following
the OpenCTI connector SDK patterns.
"""

# pylint: disable=too-few-public-methods

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the BaseExternalImportConnectorConfig to add parameters
    and/or defaults specific to the USTA connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="USTA",
    )
    scope: str = Field(
        description="The scope of the connector.",
        default="indicator,observable,malware,identity,incident,user-account,report,threat-actor",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs.",
        default=timedelta(minutes=30),
    )


class UstaConfig(BaseConfigModel):
    """
    Define parameters specific to the USTA connector.
    """

    api_base_url: HttpUrl = Field(
        description="USTA API base URL.",
        default="https://usta.prodaft.com",
    )
    api_key: str = Field(
        description="USTA API bearer token for authentication.",
    )
    import_start_date: timedelta = Field(
        description=(
            "ISO 8601 duration string specifying how far back to import data "
            "(e.g., P90D for 90 days, P30D for 30 days). "
            "Only used on the very first run when no state exists."
        ),
        default=timedelta(days=90),
    )
    page_size: int = Field(
        description="Number of records to fetch per API page.",
        default=100,
        ge=1,
        le=500,
    )
    import_malicious_urls: bool = Field(
        description="Enable import of malicious URL indicators.",
        default=True,
    )
    import_phishing_sites: bool = Field(
        description="Enable import of phishing site indicators.",
        default=True,
    )
    import_malware_hashes: bool = Field(
        description="Enable import of malware hash indicators.",
        default=True,
    )
    import_compromised_credentials: bool = Field(
        description=(
            "Enable import of compromised credentials tickets "
            "(Account Takeover Prevention)."
        ),
        default=True,
    )
    import_credit_cards: bool = Field(
        description="Enable import of compromised credit card tickets (Fraud Intelligence).",
        default=True,
    )
    import_deep_sight_tickets: bool = Field(
        description=(
            "Enable import of Deep Sight intelligence tickets "
            "(threat reports, leaks, APT activity)."
        ),
        default=True,
    )
    store_credential_password: bool = Field(
        description=(
            "When enabled, the raw password from Account Takeover Prevention "
            "records is stored in the STIX User-Account credential field. "
            "Disabled by default for security reasons."
        ),
        default=False,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "red"] = Field(
        description="TLP marking level to apply to imported data.",
        default="red",
    )
    confidence_level: int = Field(
        description="Confidence level for created STIX objects (0-100).",
        default=99,
        ge=0,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Main settings class that combines all configuration sections.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    usta: UstaConfig = Field(default_factory=UstaConfig)
