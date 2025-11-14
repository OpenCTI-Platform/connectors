from typing import Any

from connectors_sdk import BaseConnectorSettings, BaseInternalEnrichmentConnectorConfig
from connectors_sdk.core.pydantic import ListFromString
from pydantic import BaseModel, Field, Json
from pydantic_settings import BaseSettings


class Definition(BaseModel):
    scopes: list[str]
    rules: list[dict[str, Any]]


class ConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseConnectorConfig` to add connector specific configuration parameters and/or defaults.
    """

    id: str = Field(
        default="tagger--b5970f8a-ce4b-4497-a381-20b7256f5777",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Tagger",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["report", "malware", "tool"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    auto: bool = Field(
        default=True,
        description="If True, the connector will automatically import data from the API.",
    )


class TaggerConfig(BaseSettings):
    """
    Define config vars specific to Tagger connector.
    """

    definitions: Json[list[Definition]] = Field(
        default='[{"scopes":["Report","Tool"],"rules":[{"label":"cloud","search":"[Cc]loud","attributes":["name","description"]},{"label":"mobile","search":"mobile|android|apk","flags":["IGNORECASE"],"attributes":["name","description"]}]},{"scopes":["Malware"],"rules":[{"label":"windows","search":"registry|regkey","flags":["IGNORECASE"],"attributes":["description"]}]}]',
        description="Definitions array in JSON format",
    )


class ConfigLoader(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include additional configuration parameters specific to the connector.
    """

    connector: ConnectorConfig = Field(default_factory=ConnectorConfig)
    tagger: TaggerConfig = Field(default_factory=TaggerConfig)
