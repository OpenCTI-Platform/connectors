"""OpenCTI RST Noise Control connector settings module."""

from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    DeprecatedField,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import AliasChoices, Field, SecretStr


class RSTNoiseControlConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults of the `connector` section for the RST Noise Control connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="04543793-50e8-4d02-b472-e88a62e8f161",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RST Noise Control",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr", "Domain-Name", "Url", "StixFile", "indicator"],
    )
    max_tlp: TLPLevel = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLPLevel.AMBER_STRICT,
    )


class RSTNoiseControlConfig(BaseConfigModel):
    """Settings specific to the RST Noise Control connector."""

    base_url: str = Field(
        description="RST Cloud API base URL.",
        default="https://api.rstcloud.net/v1",
    )
    api_key: SecretStr = Field(
        description="RST Cloud API key.",
    )
    timeout: int = Field(
        description="RST Cloud API request timeout, in seconds.",
        default=10,
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="The maximum TLP of the entities the connector is allowed to enrich.",
    )
    update_confidence: bool = Field(
        description="Whether to reduce the confidence of indicators flagged as noisy or benign.",
        default=True,
    )
    update_score: bool = Field(
        description="Whether to reduce the score of indicators flagged as noisy or benign.",
        default=True,
    )
    change_action_score_change: int = Field(
        description="Amount by which the score (and confidence) is reduced when the action is 'Change Score'.",
        default=10,
    )
    drop_action_score_change: int = Field(
        description="Amount by which the score (and confidence) is reduced when the action is 'Drop'.",
        default=50,
    )
    drop_action_detection_flag: bool = Field(
        description="Whether to unset the detection flag of indicators when the action is 'Drop'.",
        default=True,
    )


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    """Settings of the RST Noise Control connector."""

    connector: RSTNoiseControlConnectorConfig = Field(
        default_factory=RSTNoiseControlConnectorConfig
    )
    rst_noise_control: RSTNoiseControlConfig = Field(
        default_factory=RSTNoiseControlConfig,
        # The legacy `config.yml` section is named `rst-noise-control`
        validation_alias=AliasChoices("rst_noise_control", "rst-noise-control"),
    )
