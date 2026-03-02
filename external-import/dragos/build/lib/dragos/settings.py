from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import (
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    SecretStr,
    TypeAdapter,
)


def iso_string_validator(value: str) -> datetime:
    """
    Convert ISO string into a datetime object.

    Example:
        > value = iso_string_validator("2023-10-01T00:00:00Z")
        > print(value) # 2023-10-01 00:00:00+00:00

        # If today is 2023-10-01:
        > value = iso_string_validator("P30D")
        > print(value) # 2023-09-01 00:00:00+00:00
    """
    if isinstance(value, str):
        try:
            # Convert presumed ISO string to datetime object
            return datetime.fromisoformat(value).astimezone(tz=timezone.utc)
        except ValueError:
            # If not a datetime ISO string, try to parse it as timedelta with pydantic first
            duration = TypeAdapter(timedelta).validate_python(value)
            # Then return a datetime minus the value
            return datetime.now(timezone.utc) - duration
    return value


DatetimeFromIsoString = Annotated[
    datetime,
    BeforeValidator(iso_string_validator),
    # Replace the default serializer as it uses Z prefix instead of +00:00 offset
    PlainSerializer(datetime.isoformat, when_used="json"),
]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A unique UUIDv4 identifier for this connector instance.",
        default="5147f35a-4fe8-4f43-82c2-8158f0175000",
        min_length=1,
    )
    name: str = Field(
        description="The name of the connector.",
        default="Dragos",
    )
    scope: ListFromString = Field(
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
        default=["dragos"],
        min_length=1,
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DragosConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DragosConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="Dragos API base URL.",
        default=HttpUrl("https://portal.dragos.com"),
    )
    api_token: SecretStr = Field(
        description="Dragos API token.",
    )
    api_secret: SecretStr = Field(
        description="Dragos API secret.",
    )
    import_start_date: DatetimeFromIsoString = Field(
        description="Start date of first import (ISO format). Can be a relative or an absolute date.",
        default_factory=lambda: iso_string_validator("P30D"),  # 30 days ago
    )
    tlp_level: Literal[
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="TLP level to apply on objects imported into OpenCTI.",
        default="amber+strict",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `DragosConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    dragos: DragosConfig = Field(default_factory=DragosConfig)
