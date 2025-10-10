import os
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

import __main__
from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    PlainSerializer,
    model_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
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


def comma_separated_dict_validator(value: str | list[str]) -> dict[str, str]:
    """
    Convert comma-separated string into a dict.

    Example:
        > values = comma_separated_dict_validator("key_1=value_1,key_2=value_2")
        > print(values) # { "key_1": "value_1", "key_2"="value_2" }
    """
    if isinstance(value, str):
        parsed_dict = {}
        if len(value):
            entries = [string.strip() for string in value.split(",")]
            for entry in entries:
                entry_key, entry_value = entry.split("=")
                parsed_dict[entry_key] = entry_value
        return parsed_dict
    return value


def pycti_dict_serializer(value: list[str], info: SerializationInfo) -> str | list[str]:
    """
    Serialize dict as comma-separated string.

    Example:
        > serialized_values = pycti_dict_serializer({ "key_1": "value_1", "key_2"="value_2" })
        > print(serialized_values) # "key_1=value_1,key_2=value_2"
    """
    if isinstance(value, dict) and info.context and info.context.get("mode") == "pycti":
        entries = [
            f"{entry_key}={entry_value}"
            for entry_key, entry_value in list(value.items())
        ]
        return ",".join(entries)
    return value


DictFromString = Annotated[
    dict[str, str],
    BeforeValidator(comma_separated_dict_validator),
    PlainSerializer(pycti_dict_serializer, when_used="json"),
]


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
    # Parse ISO string first
    if isinstance(value, str):
        value = datetime.fromisoformat(value)

    # Set timezone
    if isinstance(value, datetime):
        if value.tzinfo:
            value = value.astimezone(tz=timezone.utc)
        else:  # assumes ISO string represented UTC datetime
            value = value.replace(tzinfo=timezone.utc)

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
        "warn",  # alias of warning
        "warning",
        "error",
    ] = Field(default="error")


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
    client_cert: str | None = Field(
        description="Filepath to the client certificate to use for MISP API calls. Required if `ssl_verify` is enabled.",
        default=None,
    )
    reference_url: str | None = Field(
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
    datetime_attribute: Literal[
        "date",
        "timestamp",
        "publish_timestamp",
        "sighting_timestamp",
    ] = Field(
        description="The attribute to use as MISP events date.",
        default="timestamp",
    )
    # TODO: check if Literal is correct
    date_filter_field: Literal["date_from", "timestamp"] = Field(
        description="The attribute to use as filter to query new MISP events by date.",
        default="timestamp",
    )
    # ? What does it means??
    report_description_attribute_filters: DictFromString = Field(
        description="Filter to use to find the attribute that will be used for report description (example: 'type=comment,category=Internal reference')",
        default={},
        alias="report_description_attribute_filter",  # backward compatibility with mispelled env var
    )
    create_object_observables: bool = Field(
        description="Whether to create a text observable for each MISP Event's object or not.",
        default=False,
    )
    create_tags_as_labels: bool = Field(
        description="Whether to create labels from MISP tags or not.",
        default=True,
    )
    # ! Not documented in README
    guess_threats_from_tags: bool = Field(
        description="Whether to **guess** and create Threats from MISP tags or not.",
        default=False,
        alias="guess_threat_from_tags",  # backward compatibility with mispelled env var
    )
    # ! Not documented in README
    author_from_tags: bool = Field(
        description="Whether to create Authors from MISP tags or not.",
        default=False,
    )
    # ! Not documented in README
    markings_from_tags: bool = Field(
        description="Whether to create Markings from MISP tags or not.",
        default=False,
    )
    # ! Not documented in README
    keep_original_tags_as_label: ListFromString = Field(
        description="List of original MISP tags to keep as labels.",
        default=[],
    )
    # ! Not documented in README
    enforce_warning_list: bool = Field(
        description="Whether to enforce the warning list for MISP events or not.",
        default=False,
    )
    # ! Documented as MISP_REPORT_CLASS in README
    report_type: str = Field(
        description="The type of report to create on OpenCTI from MISP events.",
        default="misp-event",
    )
    import_from_date: SafeAwareDatetime | None = Field(
        description="A date (ISO-8601) from which to start importing MISP events (based on events creation date).",
        default=None,
    )
    import_tags: ListFromString = Field(
        description="List of tags to filter MISP events to import, **including** only events with these tags.",
        default=[],
    )
    import_tags_not: ListFromString = Field(
        description="List of tags to filter MISP events to import, **excluding** events with these tags.",
        default=[],
    )
    import_creator_orgs: ListFromString = Field(
        description="List of organization identifiers to filter MISP events to import, **including** only events created by these organizations.",
        default=[],
    )
    import_creator_orgs_not: ListFromString = Field(
        description="List of organization identifiers to filter MISP events to import, **excluding** events created by these organizations.",
        default=[],
    )
    import_owner_orgs: ListFromString = Field(
        description="List of organization identifiers to filter MISP events to import, **including** only events owned by these organizations.",
        default=[],
    )
    import_owner_orgs_not: ListFromString = Field(
        description="List of organization identifiers to filter MISP events to import, **excluding** events owned by these organizations.",
        default=[],
    )
    import_keyword: str | None = Field(
        description="Keyword to use as filter to import MISP events.",
        default=None,
    )
    import_distribution_levels: ListFromString = Field(
        description="List of distribution levels to filter MISP events to import, **including** only events with these distribution levels.",
        default=[],
    )
    import_threat_levels: ListFromString = Field(
        description="List of threat levels to filter MISP events to import, **including** only events with these threat levels.",
        default=[],
    )
    import_only_published: bool = Field(
        description="Whether to only import published MISP events or not.",
    )
    import_with_attachments: bool = Field(
        description="Whether to import attachment attribute content as a file (works only with PDF).",
        default=False,
    )
    import_to_ids_no_score: int = Field(
        description="A score value for the indicator/observable if the attribute `to_ids` value is no.",
    )
    import_unsupported_observables_as_text: bool = Field(
        description="Whether to import unsupported observable as x_opencti_text or not.",
        default=False,
    )
    import_unsupported_observables_as_text_transparent: bool = Field(
        description="Whether to import unsupported observable as x_opencti_text or not (just with the value).",
        default=True,
    )
    propagate_labels: bool = Field(
        description="Whether to apply labels from MISP events to OpenCTI observables on top of MISP Attribute labels or not.",
        default=False,
    )


class ConfigLoader(BaseSettings):
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
