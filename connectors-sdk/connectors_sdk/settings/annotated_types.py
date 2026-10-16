"""Commonly used Pydantic types with custom validation and serialization logic."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import (
    BeforeValidator,
    PlainSerializer,
    TypeAdapter,
    WithJsonSchema,
)


def parse_comma_separated_list(value: str | list[str]) -> list[str]:
    """Coerce a comma-separated string into a list[str], trimming surrounding
    whitespace for each element.
    If the input is already a list[str], it is returned unchanged.

    This is useful for values originating from environment variables or other
    string-based sources (e.g., "a, b , c") and converts them to ["a", "b", "c"].

    Parameters
    - value: Either a string (e.g., "a,b,c") or a list[str].

    Returns:
    - A list of strings. For string inputs, the string is split on commas, each
      token is stripped of leading/trailing whitespace, and empty tokens are
      discarded.

    Examples:
    - "a, b ,c" -> ["a", "b", "c"]
    - "a, ,c" -> ["a", "c"]
    - ["a", "b"] -> ["a", "b"]
    """
    if isinstance(value, str):
        return [stripped for string in value.split(",") if (stripped := string.strip())]
    return value


ListFromString = Annotated[
    list[str],  # Final type
    BeforeValidator(parse_comma_separated_list),
    """Annotated list[str] that:
- Validates: Accepts a comma-separated string (e.g., "a,b,c") or a list[str].
  If a string is provided, it is split on commas, whitespace is trimmed for
  each item, and empty items are discarded.

Components
- BeforeValidator(parse_comma_separated_list): Converts input strings to list[str]
  early in validation.

Examples
- Validation:
    from pydantic import BaseModel

    class Model(BaseModel):
        tags: ListFromString

    Model.model_validate({"tags": "a, b , c"}).tags  # -> ["a", "b", "c"]
    Model.model_validate({"tags": ["x", "y"]}).tags  # -> ["x", "y"]
""",
]


# ISO-8601 datetime (e.g. "2023-10-01", "2023-10-01T12:30:00Z") or ISO-8601 duration
# (e.g. "P30D", "PT1H"). Kept compatible with ECMAScript regexes (`u` flag), as it is
# evaluated by OpenCTI (AJV) when validating managed connectors config.
ISO_DATETIME_OR_DURATION_PATTERN = (
    r"^(?:"
    r"\d{4}-\d{2}-\d{2}"
    r"(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}(?::?\d{2})?)?)?"
    r"|"
    r"P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?"
    r"(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?"
    r")$"
)


def parse_iso_string(value: str | datetime) -> datetime:
    """Convert ISO string into a datetime object.

    Example:
        > value = parse_iso_string("2023-10-01T00:00:00Z")
        > print(value) # 2023-10-01 00:00:00+00:00

        # If today is 2023-10-01:
        > value = parse_iso_string("P30D")
        > print(value) # 2023-09-01 00:00:00+00:00
    """
    if not isinstance(value, str):
        return value

    try:
        # Convert presumed ISO string to datetime object
        parsed_datetime = datetime.fromisoformat(value)
        if parsed_datetime.tzinfo:
            return parsed_datetime.astimezone(tz=timezone.utc)
        else:
            return parsed_datetime.replace(tzinfo=timezone.utc)
    except ValueError:
        # If not a datetime ISO string, try to parse it as timedelta with pydantic first
        duration = TypeAdapter(timedelta).validate_python(value)
        # Then return a datetime minus the value
        return datetime.now(timezone.utc) - duration


DatetimeFromIsoString = Annotated[
    datetime,
    BeforeValidator(parse_iso_string),
    # Replace the default JSON serializer, in order to use +00:00 offset instead of Z prefix
    PlainSerializer(datetime.isoformat, when_used="json"),
    # Advertise both ISO-8601 datetimes and durations in the JSON schema, as OpenCTI
    # validates managed connectors config against it (a `format` accepts only one)
    WithJsonSchema({"type": "string", "pattern": ISO_DATETIME_OR_DURATION_PATTERN}),
    """Annotated datetime that:
- Validates: Accepts an ISO-8601 string (datetime or duration).
  If a datetime ISO-8601 string is provided, and no timezone is present, the string
  is assumed to be UTC timezoned.
  If a duration ISO-8601 string is provided, the returned datetime will be relative
  to `datetime.now(timezone.utc)` at runtime.
- Serializes (JSON): Serializes a datetime object to an datetime ISO-8601 string.
- JSON schema: Advertises a string matching either an ISO-8601 datetime or an
  ISO-8601 duration (`ISO_DATETIME_OR_DURATION_PATTERN`). Prefer a duration string
  as field default (e.g. `default="P30D"`) so that it is kept in the schema.

Components
- BeforeValidator(parse_iso_string): Converts input strings to datetime
  early in validation.
- PlainSerializer(datetime.isoformat, when_used="json"): Produces the datetime ISO-8601 string
  for JSON serialization.
- WithJsonSchema({"type": "string", "pattern": ISO_DATETIME_OR_DURATION_PATTERN}):
  Produces the JSON schema accepting both ISO-8601 datetimes and durations.

Examples
- Validation:
    from pydantic import BaseModel

    class Model(BaseModel):
        start_date: DatetimeFromIsoString

    Model.model_validate({
        "start_date": "2023-10-01"
    }).start_date  # -> datetime(2023, 10, 01, 0, 0, tzinfo=timezone.utc)
    Model.model_validate({
        "start_date": datetime(2023, 10, 01, 0, 0, tzinfo=timezone.utc)
    }).start_date  # ->  datetime(2023, 10, 01, 0, 0, tzinfo=timezone.utc)

- Serialization:
    m = Model.model_validate({"start_date": datetime(2023, 10, 01, 0, 0, tzinfo=timezone.utc)})
    m.model_dump()                               # -> {'start_date': datetime(2023, 10, 01, 0, 0, tzinfo=timezone.utc)}
    m.model_dump_json()                          # -> {"start_date": "2023-10-01T00:00:00+00:00"}
""",
]
