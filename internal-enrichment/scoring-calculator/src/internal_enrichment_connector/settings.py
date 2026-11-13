"""OpenCTI Scoring Calculator connector settings module."""

import json
from typing import Annotated, Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import BeforeValidator, Field, Json


def _yaml_list_to_json(value: Any) -> Any:
    """Turn a legacy `config.yml` value into the JSON text `Json[list[str]]` expects.

    Environment variables give a JSON array as a string, while `config.yml` gives a
    native YAML list. An empty field (`high_priority_labels:`) gives `None` or an
    empty string, which previously meant "no label".
    """
    if value is None or value == "":
        return "[]"
    if isinstance(value, list):
        return json.dumps(value)
    return value


LabelList = Annotated[Json[list[str]], BeforeValidator(_yaml_list_to_json)]


class ScoringCalculatorConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults of the `connector` section for the Scoring Calculator connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="1f5865dc-085a-4b71-98a5-58ad6f03acf5",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Scoring calculator",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Indicator"],
    )


class ScoringCalculatorConfig(BaseConfigModel):
    """Settings specific to the Scoring Calculator connector."""

    high_priority_labels: LabelList = Field(
        description=(
            "JSON array of labels marking an entity as high priority, "
            'e.g. ["[Scoring] High priority"].'
        ),
        default="[]",
    )
    medium_priority_labels: LabelList = Field(
        description=(
            "JSON array of labels marking an entity as medium priority, "
            'e.g. ["[Scoring] Medium priority"].'
        ),
        default="[]",
    )
    low_priority_labels: LabelList = Field(
        description=(
            "JSON array of labels marking an entity as low priority, "
            'e.g. ["[Scoring] Low priority"].'
        ),
        default="[]",
    )
    indicator_type_enrichable: str = Field(
        description="Comma-separated list of main observable types of the Indicators to enrich.",
        default="IPv4-Addr,IPv6-Addr,Domain-Name,StixFile",
    )
    browse_report: bool = Field(
        description="Whether to take into account the entities contained in the Reports containing the Indicator.",
        default=False,
    )

    threat_impact_score: bool = Field(
        description="Whether the related threats (Intrusion Sets, Threat Actors) impact the score.",
        default=False,
    )
    threat_high_priority: int = Field(
        description="Impact (%) on the score of a threat categorized as high priority.",
        default=0,
    )
    threat_medium_priority: int = Field(
        description="Impact (%) on the score of a threat categorized as medium priority.",
        default=0,
    )
    threat_low_priority: int = Field(
        description="Impact (%) on the score of a threat categorized as low priority.",
        default=0,
    )

    toolbox_impact_score: bool = Field(
        description="Whether the related toolbox (Malware, Tools) impacts the score.",
        default=False,
    )
    toolbox_high_priority: int = Field(
        description="Impact (%) on the score of a toolbox categorized as high priority.",
        default=0,
    )
    toolbox_medium_priority: int = Field(
        description="Impact (%) on the score of a toolbox categorized as medium priority.",
        default=0,
    )
    toolbox_low_priority: int = Field(
        description="Impact (%) on the score of a toolbox categorized as low priority.",
        default=0,
    )

    location_impact_score: bool = Field(
        description="Whether the related locations (Countries, Regions) impact the score.",
        default=False,
    )
    location_high_priority: int = Field(
        description="Impact (%) on the score of a location categorized as high priority.",
        default=0,
    )
    location_medium_priority: int = Field(
        description="Impact (%) on the score of a location categorized as medium priority.",
        default=0,
    )
    location_low_priority: int = Field(
        description="Impact (%) on the score of a location categorized as low priority.",
        default=0,
    )

    sector_impact_score: bool = Field(
        description="Whether the related sectors impact the score.",
        default=False,
    )
    sector_high_priority: int = Field(
        description="Impact (%) on the score of a sector categorized as high priority.",
        default=0,
    )
    sector_medium_priority: int = Field(
        description="Impact (%) on the score of a sector categorized as medium priority.",
        default=0,
    )
    sector_low_priority: int = Field(
        description="Impact (%) on the score of a sector categorized as low priority.",
        default=0,
    )

    ttp_impact_score: bool = Field(
        description="Whether the related TTPs (Attack Patterns) impact the score.",
        default=False,
    )
    ttp_high_priority: int = Field(
        description="Impact (%) on the score of a TTP categorized as high priority.",
        default=0,
    )
    ttp_medium_priority: int = Field(
        description="Impact (%) on the score of a TTP categorized as medium priority.",
        default=0,
    )
    ttp_low_priority: int = Field(
        description="Impact (%) on the score of a TTP categorized as low priority.",
        default=0,
    )

    author_impact_score: bool = Field(
        description="Whether the author (Organization) impacts the score.",
        default=False,
    )
    author_high_priority: int = Field(
        description="Impact (%) on the score of an author categorized as high priority.",
        default=0,
    )
    author_medium_priority: int = Field(
        description="Impact (%) on the score of an author categorized as medium priority.",
        default=0,
    )
    author_low_priority: int = Field(
        description="Impact (%) on the score of an author categorized as low priority.",
        default=0,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Scoring Calculator connector."""

    connector: ScoringCalculatorConnectorConfig = Field(
        default_factory=ScoringCalculatorConnectorConfig
    )
    connector_scoring: ScoringCalculatorConfig = Field(
        default_factory=ScoringCalculatorConfig
    )
