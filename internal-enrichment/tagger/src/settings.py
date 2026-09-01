import re

from connectors_sdk import (
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import BaseModel, Field, Json, PrivateAttr, model_validator
from pydantic_settings import BaseSettings


class Rule(BaseModel):
    label: str
    search: str
    flags: list[str] = Field(default_factory=list)
    attributes: list[str]
    # Compiled once at load time so patterns are validated before the connector
    # starts consuming messages and are not re-resolved on every call. Kept as a
    # private attribute so it stays out of model_dump() and the JSON schema.
    _pattern: re.Pattern = PrivateAttr()

    @model_validator(mode="after")
    def compile_pattern(self) -> "Rule":
        flags = 0
        for flag_name in self.flags:
            flag = getattr(re, flag_name, None)
            if not isinstance(flag, re.RegexFlag):
                raise ValueError(
                    f"Invalid regex flag {flag_name!r} in rule {self.label!r}"
                )
            flags |= flag

        try:
            self._pattern = re.compile(self.search, flags)
        except re.error as exc:
            raise ValueError(
                f"Invalid regular expression {self.search!r} in rule {self.label!r}: {exc}"
            ) from exc

        return self

    @property
    def pattern(self) -> re.Pattern:
        return self._pattern


class Definition(BaseModel):
    scopes: list[str]
    rules: list[Rule]


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
