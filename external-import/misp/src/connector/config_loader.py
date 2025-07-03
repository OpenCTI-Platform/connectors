import os
import warnings
from abc import ABC
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional

import __main__
from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    TypeAdapter,
    ValidationError,
    model_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_MAIN_PATH_ = os.path.dirname(os.path.abspath(__main__.__file__))

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
    
    the split is made on the first occurrence of the "_" character.
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


def safe_aware_datetime_validator(value: str | datetime) -> AwareDatetime:
    """
    Validate and convert a string or datetime into an aware datetime object.

    Example:
        > aware_datetime = safe_aware_datetime_validator("2023-10-01T12:00:00Z")
        > print(aware_datetime) # 2023-10-01 12:00:00+00:00
    """
    if isinstance(value, datetime):
        return value.astimezone(tz=timezone.utc)
    if isinstance(value, str):
        try:
            return TypeAdapter(AwareDatetime).validate_python(value)
        except ValidationError as exc:
            print(repr(exc.errors()[0]["type"]))
            # > 'timezone_aware'
            return datetime.fromisoformat(value).astimezone(tz=timezone.utc)

    return value


SafeAwareDatetime = Annotated[
    AwareDatetime,
    BeforeValidator(safe_aware_datetime_validator),
]


class _ConfigBaseModel(BaseModel):
    """
    Base class for frozen config models, i.e. not alter-able after `model_post_init()`.
    """

    model_config = ConfigDict(frozen=True, extra="allow")


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

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'misp'.",
        default=["misp"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )

    log_level: Literal[
        "debug",
        "info",
        "warning",
        "error",
        "critical",
    ] = Field(default="error")
    auto: bool = Field(default=False)
    expose_metrics: bool = Field(default=False)
    metrics_port: int = Field(default=9095)
    only_contextual: bool = Field(default=False)
    run_and_terminate: bool = Field(default=False)
    validate_before_import: bool = Field(default=False)
    queue_protocol: str = Field(default="amqp")
    queue_threshold: int = Field(default=500)

    send_to_queue: bool = Field(default=True)
    send_to_directory: bool = Field(default=False)
    send_to_directory_path: str | None = Field(default=None)
    send_to_directory_retention: int = Field(default=7)


class _MISPConfig(_ConfigBaseModel):
    """
    Define config specific to MISP connector.
    """

    url: str = Field(description="MISP instance URL")
    key: str = Field(
        description="MISP instance API key.",
    )
    ssl_verify: bool = Field(
        description="Whether to check if the SSL certificate is valid when using `HTTPS` protocol or not.",
    )
    client_cert: Optional[str] = Field(
        description="Filepath to the client certificate to use for MISP API calls. Required if `ssl_verify` is enabled.",
        default=None,
    )
    reference_url: Optional[str] = Field(
        description="MISP base URL used for External References",
        default=None,
    )
    create_reports: bool = Field(
        description="Whether to create reports for each imported MISP event or not.",
    )
    create_indicators: bool = Field(
        description="Whether to create an indicator for each imported MISP attribute or not.",
    )
    create_observables: bool = Field(
        description="Whether to create an observable for each imported MISP attribute or not.",
    )
    # TODO: replace str type by literal of accepted values
    datetime_attribute: Optional[str] = Field(
        description="The attribute to use as MISP events date.",
        default="timestamp",
    )
    # TODO: replace str type by literal of accepted values
    date_filter_field: Optional[str] = Field(
        description="The attribute to use as filter to query new MISP events by date.",
        default="timestamp",
    )
    # TODO: check if it's optional or required - use json.loads for parsing
    # ? What does it means??
    report_description_attribute_filter: Optional[dict] = Field(
        description="Filter to use to find the attribute with report description (example: 'type=comment,category=Internal reference')",
        default={},
    )
    # ? What does it means??
    create_object_observables: Optional[bool] = Field(
        description="Whether to create a text observable for each imported MISP object or not.",
        default=False,
    )
    create_tags_as_labels: Optional[bool] = Field(
        description="Whether to create labels from MISP tags or not.",
        default=True,
    )
    # ! Not documented in README
    guess_threats_from_tags: Optional[bool] = Field(
        description="Whether to **guess** and create Threats from MISP tags or not.",
        default=False,
    )
    # ! Not documented in README
    author_from_tags: Optional[bool] = Field(
        description="Whether to create Authors from MISP tags or not.",
        default=False,
    )
    # ! Not documented in README
    markings_from_tags: Optional[bool] = Field(
        description="Whether to create Markings from MISP tags or not.",
        default=False,
    )
    # ! Not documented in README
    keep_original_tags_as_label: Optional[ListFromString] = Field(
        description="List of original MISP tags to keep as labels.",
        default=[],
    )
    # ! Not documented in README
    enforce_warning_list: Optional[bool] = Field(
        description="Whether to enforce the warning list for MISP events or not.",
        default=False,
    )
    # TODO: replace str type with literal of accepted values
    # ! Documented as MISP_REPORT_CLASS in README
    report_type: Optional[str] = Field(
        description="The type of report to create from MISP events.",
        default="misp-event",
    )
    import_from_date: Optional[SafeAwareDatetime] = Field(
        description="A date (ISO-8601) from which to start importing MISP events (based on events creation date).",
        default=None,
    )
    import_tags: Optional[ListFromString] = Field(
        description="List of tags to filter MISP events to import, **including** only events with these tags.",
        default=[],
    )
    import_tags_not: Optional[ListFromString] = Field(
        description="List of tags to filter MISP events to import, **excluding** events with these tags.",
        default=[],
    )
    import_creator_orgs: Optional[ListFromString] = Field(
        description="List of organization identifiers to filter MISP events to import, **including** only events created by these organizations.",
        default=[],
    )
    import_creator_orgs_not: Optional[ListFromString] = Field(
        description="List of organization identifiers to filter MISP events to import, **excluding** events created by these organizations.",
        default=[],
    )
    import_owner_orgs: Optional[ListFromString] = Field(
        description="List of organization identifiers to filter MISP events to import, **including** only events owned by these organizations.",
        default=[],
    )
    import_owner_orgs_not: Optional[ListFromString] = Field(
        description="List of organization identifiers to filter MISP events to import, **excluding** events owned by these organizations.",
        default=[],
    )
    import_keyword: Optional[str] = Field(
        description="Keyword to use as filter to import MISP events.",
        default=None,
    )
    import_distribution_levels: Optional[ListFromString] = Field(
        description="List of distribution levels to filter MISP events to import, **including** only events with these distribution levels.",
        default=[],
    )
    import_threat_levels: Optional[ListFromString] = Field(
        description="List of threat levels to filter MISP events to import, **including** only events with these threat levels.",
        default=[],
    )
    import_only_published: bool = Field(
        description="Whether to only import published MISP events or not.",
    )
    import_with_attachments: Optional[bool] = Field(
        description="Whether to import attachment attribute content as a file (works only with PDF).",
        default=False,
    )
    # ? What does it mean ??
    import_to_ids_no_score: int = Field(
        description="A score value for the indicator/observable if the attribute `to_ids` value is no.",
    )
    # ? What does it mean ??
    import_unsupported_observables_as_text: Optional[bool] = Field(
        description="Whether to import unsupported observable as x_opencti_text or not.",
        default=False,
    )
    # ? What does it mean ??
    import_unsupported_observables_as_text_transparent: Optional[bool] = Field(
        description="Whether to import unsupported observable as x_opencti_text or not (just with the value).",
        default=True,
    )
    # ? What does it mean ??
    propagate_labels: Optional[bool] = Field(
        description="Whether to apply labels from MISP events to OpenCTI observables on top of MISP Attribute labels or not.",
        default=False,
    )


class ConfigLoader(BaseSettings, ABC):
    """
    Define a complete config for a connector with:
        - opencti: the config specific to OpenCTI
        - connector: the config specific to the `external-import` connectors
        - misp: the config specific to the MISP connector
    """

    opencti: _OpenCTIConfig
    connector: _ConnectorConfig
    misp: _MISPConfig

    # Setup model config and env vars parsing
    model_config = SettingsConfigDict(
        frozen=True,
        extra="allow",
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{_MAIN_PATH_}/config.yml",
        env_file=f"{_MAIN_PATH_}/../.env",
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

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `MISP_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        misp_data: dict = data.get("misp", {})

        if interval := misp_data.pop("interval", None):
            warnings.warn(
                "Env var 'MISP_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(minutes=int(interval))

        return data
