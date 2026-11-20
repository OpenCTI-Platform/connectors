"""OpenCTI Sekoia.io connector settings module."""

from datetime import timedelta
from typing import Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, PositiveInt, SecretStr, model_validator


class SekoiaConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Sekoia.io connector."""

    id: str = Field(
        description="A unique UUIDv4 identifier for this connector instance.",
        default="sekoia--8c694370-34bb-4f5d-a934-856779a473a0",
    )
    name: str = Field(
        description="Name of the connector.",
        default="SEKOIA.IO",
    )
    scope: ListFromString = Field(
        description=(
            "The scope or type of data the connector is importing, "
            "either a MIME type or Stix Object (for information only)."
        ),
        default=[
            "identity",
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "malware",
            "tool",
            "report",
            "location",
            "vulnerability",
            "indicator",
            "campaign",
            "infrastructure",
            "relationship",
        ],
    )
    duration_period: timedelta = Field(
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
        default=timedelta(seconds=60),
    )


class SekoiaConfig(BaseConfigModel):
    """Settings specific to the Sekoia.io connector."""

    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the Sekoia service.",
    )
    base_url: str = Field(
        description="Base URL for accessing the Sekoia API.",
        default="https://api.sekoia.io",
    )
    collection: str = Field(
        description=(
            "Allows you to specify the collection to query in order to retrieve "
            "or manage indicators of compromise."
        ),
        default="d6092c37-d8d7-45c3-8aff-c4dc26030608",
    )
    start_date: str | None = Field(
        description=(
            "The date to start consuming data from. "
            "May be in the formats YYYY-MM-DD or YYYY-MM-DDT00:00:00."
        ),
        default=None,
    )
    limit: PositiveInt = Field(
        description="The number of elements to fetch in each request. Defaults to 200, maximum 2000.",
        default=200,
    )
    create_observables: bool = Field(
        description="Create observables from indicators.",
        default=True,
    )
    import_source_list: bool = Field(
        description="Create the list of sources observed by Sekoia as label.",
        default=False,
    )
    import_ioc_relationships: bool = Field(
        description="Import IOCs relationships and related objects.",
        default=True,
    )
    confidence_score: int | None = Field(
        description="This will be the score assigned to the indicators. Defaults to null, maximum 100.",
        default=None,
    )
    send_confidence: bool = Field(
        description="Whether to include Sekoia's native STIX confidence property on objects in the bundle sent.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Sekoia.io connector."""

    connector: SekoiaConnectorConfig = Field(default_factory=SekoiaConnectorConfig)
    sekoia: SekoiaConfig = Field(default_factory=SekoiaConfig)

    @model_validator(mode="before")
    @classmethod
    def _strip_and_ignore_empty_values(cls, data: Any) -> Any:
        """Remove spaces around text values, then ignore empty values.

        The connector did this before it used connectors-sdk.
        A space or a new line around an API key no longer breaks it.
        An empty value uses the default value: for example,
        `SEKOIA_LIMIT=` gives the default limit, not an error.
        """
        if not isinstance(data, dict):
            return data
        cleaned_data = {}
        for section, values in data.items():
            if isinstance(values, dict):
                values = {
                    key: value.strip() if isinstance(value, str) else value
                    for key, value in values.items()
                }
                values = {key: value for key, value in values.items() if value != ""}
            cleaned_data[section] = values
        return cleaned_data
