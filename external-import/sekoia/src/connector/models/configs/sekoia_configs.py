import logging
import re
from datetime import date, datetime, timezone
from typing import Annotated, Any

from connectors_sdk import DatetimeFromIsoString
from connectors_sdk.settings.annotated_types import ISO_DATETIME_OR_DURATION_PATTERN
from dateutil.parser import parse as dateutil_parse
from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    PositiveInt,
    SecretStr,
    field_validator,
)
from src.connector.models.configs import ConfigBaseSettings

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]

# Same flags as the SDK: `\d` only matches 0-9.
_ISO_DATETIME_OR_DURATION_REGEX = re.compile(ISO_DATETIME_OR_DURATION_PATTERN, re.ASCII)

logger = logging.getLogger(__name__)


def _to_utc(value: datetime) -> datetime:
    """Return a UTC aware datetime, a naive one being considered as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class _ConfigLoaderSekoia(ConfigBaseSettings):
    """Interface for loading Sekoia dedicated configuration."""

    # Config Loader
    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the Sekoia service.",
    )
    base_url: str = Field(
        default="https://api.sekoia.io",
        description="Base URL for accessing the Sekoia API.",
    )
    collection: str = Field(
        default="d6092c37-d8d7-45c3-8aff-c4dc26030608",
        description="Allows you to specify the collection to query in order to retrieve or manage indicators of compromise.",
    )
    start_date: DatetimeFromIsoString = Field(
        default="P90D",
        description="Date from which data import should start (ISO 8601 datetime or duration, e.g. '2023-10-01' or 'P90D'). Default: 90 days ago. Only used on the first run, when no state exists.",
    )
    limit: PositiveInt = Field(
        default=200,
        description="The number of elements to fetch in each request. Defaults to 200, maximum 2000.",
    )
    create_observables: bool = Field(
        default=True,
        description="Create observables from indicators.",
    )
    import_source_list: bool = Field(
        default=False,
        description="Create the list of sources observed by Sekoia as label.",
    )
    import_ioc_relationships: bool = Field(
        default=True,
        description="Import IOCs relationships and related objects.",
    )
    confidence_score: int | None = Field(
        default=None,
        description="This will be the score assigned to the indicators. Defaults to null, maximum 100.",
    )
    send_confidence: bool = Field(
        default=True,
        description="Whether to include Sekoia's native STIX confidence property on objects in the bundle sent.",
    )

    @field_validator("start_date", mode="before")
    @classmethod
    def _accept_legacy_start_date(cls, value: Any) -> Any:
        """Keep accepting non ISO 8601 dates that were valid before the SDK type.

        Strings that do not match the ISO 8601 datetime or duration pattern but
        that `dateutil` can parse (e.g. `2022/01/01`, `20220101`) are converted to
        a UTC datetime, with a deprecation warning. Anything else is passed on, so
        that the SDK validator raises a clear error.

        Unquoted YAML values are handled too: an integer such as `20220101` is read
        as text (not as a Unix timestamp), and a date or naive datetime is read as
        UTC.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            value = str(value)
        if isinstance(value, datetime):
            try:
                return _to_utc(value)
            except OverflowError as err:
                raise ValueError(
                    f"Datetime out of range, it cannot be converted to UTC: {value!r}"
                ) from err
        if isinstance(value, date):
            return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
        if not isinstance(value, str):
            return value

        # This validator runs before the whitespace stripping of the base settings
        value = value.strip()
        if _ISO_DATETIME_OR_DURATION_REGEX.fullmatch(value):
            return value
        try:
            # Out of range values (e.g. year 9999 with an offset) overflow in the UTC
            # conversion: let the SDK validator raise a clear error for them too.
            converted = _to_utc(dateutil_parse(value))
        except (ValueError, OverflowError):
            return value
        logger.warning(
            "Deprecated SEKOIA_START_DATE format: use an ISO 8601 datetime "
            "(e.g. '2023-10-01') or duration (e.g. 'P90D'). "
            "Date parts missing from the value are taken from the current date",
            extra={"start_date": value},
        )
        return converted
