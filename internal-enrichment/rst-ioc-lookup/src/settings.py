"""OpenCTI RST IoC Lookup connector settings module."""

from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    DeprecatedField,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import AliasChoices, Field, SecretStr


class RSTIocLookupConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults of the `connector` section for the RST IoC Lookup connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="39e3373c-b4e8-4706-87d6-ab867a90e740",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RST IoC Lookup",
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


class RSTIocLookupConfig(BaseConfigModel):
    """Settings specific to the RST IoC Lookup connector."""

    base_url: str = Field(
        description="The RST Cloud API base URL.",
        default="https://api.rstcloud.net/v1",
    )
    api_key: SecretStr = Field(
        description="The RST Cloud API key.",
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="The highest TLP of the entities the connector is allowed to enrich.",
    )
    update_confidence: bool = Field(
        description="Whether to set the indicator confidence to the RST Cloud source score.",
        default=True,
    )
    update_score: bool = Field(
        description="Whether to update the score of the observable or indicator.",
        default=True,
    )
    update_valid_from: bool = Field(
        description=(
            "Whether to move the indicator `valid_from` to the last seen date "
            "(and shift `valid_until` accordingly)."
        ),
        default=True,
    )
    score_type: str = Field(
        description=(
            "The RST Cloud score to use: `last` (score on the last seen day), "
            "`first` (score on the first seen day) or `total` (decayed score)."
        ),
        default="total",
    )
    update_description_action: str = Field(
        description=(
            "How to merge the RST Cloud description into the existing one: "
            "`overwrite`, `append` or `prepend`."
        ),
        default="overwrite",
    )
    detection_flag_threshold: int = Field(
        description=(
            "Score from which the indicator detection flag is set to true "
            "(below, it is set to false). `0` leaves the detection flag unchanged."
        ),
        default=45,
    )
    label_format: str = Field(
        description=(
            "Label format: `short` (suffixes such as `_group` or `_ransomware` removed) "
            "or `long` (labels kept as returned by RST Cloud)."
        ),
        default="short",
    )
    timeout: int = Field(
        description="The RST Cloud API request timeout, in seconds.",
        default=10,
    )


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    """Settings of the RST IoC Lookup connector."""

    connector: RSTIocLookupConnectorConfig = Field(
        default_factory=RSTIocLookupConnectorConfig
    )
    rst_ioc_lookup: RSTIocLookupConfig = Field(
        default_factory=RSTIocLookupConfig,
        # The legacy `config.yml` section is named `rst-ioc-lookup`
        validation_alias=AliasChoices("rst_ioc_lookup", "rst-ioc-lookup"),
    )
