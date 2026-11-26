"""OpenCTI NameShield connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class NameShieldConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the NameShield connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="46ae8578-037f-49fc-b68c-f803f1f0d86e",
    )
    name: str = Field(
        description="The name of the connector.",
        default="NameShield",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["NameShield"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=168),
    )


class NameShieldConfig(BaseConfigModel):
    """Settings specific to the NameShield connector."""

    auth_bearer: SecretStr = Field(
        description=(
            "Bearer token of the NameShield API. The IP address of the connector "
            "must also be allowed on the NameShield side."
        ),
    )
    server: str = Field(
        description="NameShield API server, used as `{server}` in the URL templates.",
        default="api.nameshield.net",
    )
    api_version: str = Field(
        description="NameShield API version, used as `{api_version}` in the URL templates.",
        default="v1",
    )
    api_endpoint: str = Field(
        description="NameShield API endpoint, used as `{api_endpoint}` in the URL templates.",
        default="registrar",
    )
    url_list: str = Field(
        description=(
            "URL template of the domain list. Supports the `{server}`, "
            "`{api_endpoint}` and `{api_version}` placeholders."
        ),
        default="https://{server}/{api_endpoint}/{api_version}/domains",
    )
    url_domain: str = Field(
        description=(
            "URL template of the domain details. Supports the `{server}`, "
            "`{api_endpoint}`, `{api_version}` and `{domain}` placeholders."
        ),
        default="https://{server}/{api_endpoint}/{api_version}/domains/{domain}",
    )
    domain_limit: int = Field(
        description="Maximum number of domains imported per run.",
        default=10000,
    )
    marking: str = Field(
        description=(
            "TLP marking applied to the imported objects: `TLP:CLEAR`, `TLP:WHITE`, "
            "`TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` or `TLP:RED`. Any other "
            "value falls back to `TLP:AMBER+STRICT`."
        ),
        default="TLP:GREEN",
    )
    link_to_identities: str = Field(
        description=(
            "Comma-separated STIX IDs of identities (for example your organization) "
            "the indicators are attributed to. Leave empty to create no link."
        ),
        default="",
    )
    interval: int | None = DeprecatedField(
        description="Time between two runs, in hours.",
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda hours: timedelta(hours=int(hours)),
        default=None,
    )
    # Former config.yml key of `marking` (the environment variable has always
    # been NAMESHIELD_MARKING).
    marking_definition: str | None = DeprecatedField(
        description="TLP marking applied to the imported objects.",
        deprecated="Use 'marking' instead.",
        new_namespaced_var="marking",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the NameShield connector."""

    connector: NameShieldConnectorConfig = Field(
        default_factory=NameShieldConnectorConfig
    )
    nameshield: NameShieldConfig = Field(default_factory=NameShieldConfig)
