import os
from pathlib import Path
from typing import Annotated, Literal

import __main__
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

MAIN_DIRECTORY_PATH = os.path.dirname(os.path.abspath(__main__.__file__))

SCOPE_ENTITIES = [
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "stixfile",
    "vulnerability",
]

VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS = [
    "aiInsights",
    "cpe",
    "risk",
]

"""
All the variables that have default values will override configuration from the OpenCTI helper.

All the variables of this classes are customizable through:
    - config.yml 
    - .env
    - environment variables.

If a variable is set in 2 different places, the first one will be used in this order:
    1. YAML file
    2. .env file
    3. Environment variables
    4. Default value
    
WARNING:
    The Environment variables in the .env or global environment must be set in the following format:
    OPENCTI_<variable>
    CONNECTOR_<variable>
    RECORDED_FUTURE_<variable>
"""


class ConfigRetrievalError(Exception):
    """Known errors wrapper for config loaders."""


def comma_separated_list_validator(value: str | list[str]) -> list[str]:
    """
    Convert comma-separated string into a list of values.

    Example:
        > values = comma_separated_list_validator("e1,e2,e3")
        > print(values) # [ "e1", "e2", "e3" ]
    """
    if isinstance(value, str):
        if len(value) == 0:
            return []
        else:
            return [string.strip() for string in value.split(",")]
    return value


def pycti_list_serializer(value: list[str], info: SerializationInfo) -> str | list[str]:
    """
    Serialize list of values as comma-separated string.

    Example:
        > serialized_values = pycti_list_serializer([ "e1", "e2", "e3" ])
        > print(serialized_values) # "e1,e2,e3"
    """
    if isinstance(value, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(value)
    return value


ListFromString = Annotated[
    list[str],
    BeforeValidator(comma_separated_list_validator),
    PlainSerializer(pycti_list_serializer, when_used="json"),
]


class _ConfigBaseModel(BaseModel):
    """
    Base class for frozen config models, i.e. not alter-able after `model_post_init()`.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="allow",
        validate_default=True,
    )


class _OpenCTIConfig(_ConfigBaseModel):
    """
    Define config specific to OpenCTI.
    """

    url: HttpUrl
    token: str
    json_logging: bool = Field(default=True)
    ssl_verify: bool = Field(default=False)


class _ConnectorConfig(_ConfigBaseModel):
    """
    Define config specific to this type of connector, e.g. an `external-import`.
    """

    id: str
    type: str = "INTERNAL_ENRICHMENT"
    name: str = Field(default="Recorded Future Enrichment")
    scope: ListFromString = Field(default=SCOPE_ENTITIES)
    log_level: Literal[
        "debug",
        "info",
        "warning",
        "error",
    ] = Field(default="error")
    auto: bool = Field(default=False)

    expose_metrics: bool = Field(default=False)
    metrics_port: int = Field(default=9095)
    only_contextual: bool = Field(default=False)
    queue_protocol: str = Field(default="amqp")
    queue_threshold: int = Field(default=500)
    validate_before_import: bool = Field(default=False)

    send_to_queue: bool = Field(default=True)
    send_to_directory: bool = Field(default=False)
    send_to_directory_path: str | None = Field(default=None)
    send_to_directory_retention: int = Field(default=7)

    @field_validator("scope", mode="after")
    @classmethod
    def validate_scope_entities(cls, scope: list[str]) -> list[str]:
        for entity in scope:
            if entity.lower() not in SCOPE_ENTITIES:
                raise ValueError("Invalid scope entity")
        return scope


class _RecordedFutureConfig(_ConfigBaseModel):
    token: str = Field(
        description="API Token for Recorded Future.",
    )
    create_indicator_threshold: int = Field(
        description="The risk score threshold at which an indicator will be created for enriched observables.",
        ge=0,
        le=100,
        default=0,
    )
    info_max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Max TLP marking of the entity to enrich (inclusive).",
        default="TLP:AMBER",
    )
    vulnerability_enrichment_optional_fields: ListFromString = Field(
        description="A list of optional fields to enrich vulnerabilities with. (For vulnerability enrichment only)",
        default=[],
    )

    @field_validator("vulnerability_enrichment_optional_fields", mode="after")
    @classmethod
    def validate_vulnerability_enrichment_optional_fields(
        cls, vulnerability_enrichment_optional_fields: list[str]
    ) -> list[str]:
        for field in vulnerability_enrichment_optional_fields:
            if field not in VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS:
                raise ValueError("Invalid vulnerability enrichment optional field(s)")
        return vulnerability_enrichment_optional_fields


class ConnectorConfig(BaseSettings):
    """
    Define a complete config for a connector with:
        - opencti: the config specific to OpenCTI client
        - connector: the config specific to the `internal-enrichment` connectors
        - recorded_future: the config specific to Recorded Future Enrichment connector
    """

    opencti: _OpenCTIConfig
    connector: _ConnectorConfig
    recorded_future: _RecordedFutureConfig

    # Setup model config and env vars parsing
    model_config = SettingsConfigDict(
        frozen=True,
        extra="allow",
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{MAIN_DIRECTORY_PATH}/config.yml",
        env_file=f"{MAIN_DIRECTORY_PATH}/../.env",
    )

    def __init__(self) -> None:
        """
        Wrap BaseConnectorConfig initialization to raise custom exception in case of error.
        """
        try:
            super().__init__()
        except Exception as e:
            raise ConfigRetrievalError("Invalid OpenCTI configuration.", e) from e

    def model_dump_pycti(self) -> dict:
        """
        Convert model into a valid dict for `pycti.OpenCTIConnectorHelper`.
        """
        return self.model_dump(mode="json", context={"mode": "pycti"})

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """
        Customise the sources of settings for the connector.

        This method is called by the Pydantic BaseSettings class to determine the order of sources

        The configuration come in this order either from:
            1. YAML file
            2. .env file
            3. Environment variables
            4. Default values
        """
        if Path(settings_cls.model_config["yaml_file"] or "").is_file():  # type: ignore
            return (YamlConfigSettingsSource(settings_cls),)
        if Path(settings_cls.model_config["env_file"] or "").is_file():  # type: ignore
            return (dotenv_settings,)
        return (env_settings,)
