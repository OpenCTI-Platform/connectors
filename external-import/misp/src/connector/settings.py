import warnings
from datetime import timedelta
from typing import Annotated, Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import (
    AfterValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    SecretStr,
    SerializationInfo,
    field_validator,
    model_validator,
)


def comma_separated_dict(value: str | dict[str, str]) -> dict[str, str]:
    """
    Convert comma-separated string into a dict.

    Example:
        > values = comma_separated_dict("key_1=value_1,key_2=value_2")
        > print(values) # { "key_1": "value_1", "key_2"="value_2" }
    """
    if isinstance(value, str):
        parsed_dict = {}
        if len(value):
            parsed_dict = {
                x.split("=")[0].lower(): str(x.split("=")[1])
                for x in value.replace(" ", "").split(",")
            }
        return parsed_dict
    return value


def pycti_dict_serializer(value: list[str], info: SerializationInfo) -> str | list[str]:
    """
    Serialize dict as comma-separated string.

    Example:
        > serialized_values = pycti_dict_serializer({ "key_1": "value_1", "key_2"="value_2" })
        > print(serialized_values) # "key_1=value_1,key_2=value_2"
    """
    if (
        isinstance(value, dict)
        and info.context
        and (info.context.get("mode") == "pycti")
    ):
        entries = [
            f"{entry_key}={entry_value}"
            for entry_key, entry_value in list(value.items())
        ]
        return ",".join(entries)
    return value


DictFromString = Annotated[
    str,
    AfterValidator(comma_separated_dict),
    PlainSerializer(pycti_dict_serializer, when_used="json"),
]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The UUID of the connector.",
        default="fae73097-aa2c-4460-96ee-1aa975ce1945",
    )
    name: str = Field(
        description="The name of the connector.",
        default="MISP",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["misp"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )


class MispConfig(BaseConfigModel):
    """
    Define config specific to MISP connector.
    """

    url: HttpUrl = Field(
        description="MISP instance URL",
    )
    key: SecretStr = Field(
        description="MISP instance API key.",
    )
    ssl_verify: bool = Field(
        description="Whether to check if the SSL certificate is valid when using `HTTPS` protocol or not.",
        default=False,
    )
    client_cert: str | None = Field(
        description="Filepath to the client certificate to use for MISP API calls. Required if `ssl_verify` is enabled.",
        default=None,
    )
    reference_url: HttpUrl | None = Field(
        description="MISP base URL used for External References",
        default=None,
    )
    create_reports: bool = Field(
        description="Whether to create reports for each imported MISP event or not.",
        default=True,
    )
    create_indicators: bool = Field(
        description="Whether to create an indicator for each imported MISP attribute or not.",
        default=True,
    )
    create_observables: bool = Field(
        description="Whether to create an observable for each imported MISP attribute or not.",
        default=True,
    )
    create_object_observables: bool = Field(
        description="Whether to create a text observable for each MISP Event's object or not.",
        default=False,
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
    date_filter_field: Literal[
        "date_from",
        "timestamp",
        "publish_timestamp",
    ] = Field(
        description="The attribute to use as filter to query new MISP events by date.",
        default="timestamp",
    )
    report_description_attribute_filters: DictFromString = Field(
        description="Filter to use to find the attribute that will be used for report description (example: 'type=comment,category=Internal reference')",
        default="",
        alias="report_description_attribute_filter",  # backward compatibility with mispelled env var
    )
    create_tags_as_labels: bool = Field(
        description="Whether to create labels from MISP tags or not.",
        default=True,
    )
    guess_threats_from_tags: bool = Field(
        description="Whether to **guess** and create Threats from MISP tags or not.",
        default=False,
        alias="guess_threat_from_tags",  # backward compatibility with mispelled env var
    )
    author_from_tags: bool = Field(
        description="Whether to create Authors from MISP tags or not.",
        default=False,
    )
    markings_from_tags: bool = Field(
        description="Whether to create Markings from MISP tags or not.",
        default=False,
    )
    keep_original_tags_as_label: ListFromString = Field(
        description="List of original MISP tags to keep as labels.",
        default=[],
    )
    enforce_warning_list: bool = Field(
        description="Whether to enforce the warning list for MISP events or not.",
        default=False,
    )
    report_type: str = Field(
        description="The type of report to create on OpenCTI from MISP events.",
        default="misp-event",
    )
    import_from_date: DatetimeFromIsoString | None = Field(
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
        default=False,
    )
    import_with_attachments: bool = Field(
        description="Whether to import attachment attribute content as a file (works only with PDF).",
        default=False,
    )
    import_to_ids_no_score: int | None = Field(
        description="A score value for the indicator/observable if the attribute `to_ids` value is no.",
        default=None,
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
    batch_count: int = Field(
        description="The max number of items per batch when splitting STIX bundles.",
        default=9999,
    )
    request_timeout: float | None = Field(
        description="The timeout for the requests to the MISP API in seconds. None means no timeout.",
        default=None,
    )

    @field_validator("reference_url", mode="before")
    @classmethod
    def validate_reference_url(cls, value: Any) -> Any:
        """Replace empty string with `None` before validation."""
        if isinstance(value, str):
            return value or None
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MispConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    misp: MispConfig = Field(default_factory=MispConfig)

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
