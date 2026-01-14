"""Commonly used Pydantic types with custom validation and serialization logic."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import (
    BeforeValidator,
    PlainSerializer,
    SerializationInfo,
    TypeAdapter,
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
    - A list of strings. For string inputs, the string is split on commas and each
      token is stripped of leading/trailing whitespace.

    Examples:
    - "a, b ,c" -> ["a", "b", "c"]
    - ["a", "b"] -> ["a", "b"]
    """
    if isinstance(value, str):
        return [string.strip() for string in value.split(",") if value]
    return value


def serialize_list_of_strings(
    value: list[str], info: SerializationInfo
) -> str | list[str]:
    """Serialize a list[str] as a comma-separated string when the Pydantic
    serialization context requests "pycti" mode; otherwise, return the list
    unchanged.

    This serializer is intended for use with Pydantic v2 `PlainSerializer` and
    is typically activated only during JSON serialization (`when_used="json"`),
    so the in-memory Python value remains a `list[str]` while the JSON output
    can be a single string when required by external systems.

    Parameters
    - value: The value to serialize. Expected to be a list of strings.
    - info: Serialization context provided by Pydantic. If `info.context`
      contains `{"mode": "pycti"}`, the list will be joined into a single
      comma-separated string.

    Returns:
    - A comma-separated string if context mode is "pycti" and `value` is a list.
    - The original value `value` unchanged in all other cases.

    Notes:
    - Joining does not insert spaces; e.g., ["a", "b", "c"] -> "a,b,c".
    - If any element contains commas, those commas are not escaped.

    Examples:
    - info.context={"mode": "pycti"} and value=["e1", "e2"] -> "e1,e2"
    - info.context is None or mode != "pycti" -> ["e1", "e2"]
    """
    if info.context and info.context.get("mode") == "pycti":
        return ",".join(value)  # [ "e1", "e2", "e3" ] -> "e1,e2,e3"
    return value


ListFromString = Annotated[
    list[str],  # Final type
    BeforeValidator(parse_comma_separated_list),
    PlainSerializer(serialize_list_of_strings, when_used="json"),
    """Annotated list[str] that:
- Validates: Accepts a comma-separated string (e.g., "a,b,c") or a list[str].
  If a string is provided, it is split on commas and whitespace is trimmed for
  each item.
- Serializes (JSON): When the Pydantic serialization context includes
  {"mode": "pycti"}, the list is serialized as a single comma-separated string
  (e.g., ["a","b"] -> "a,b"). Otherwise, it serializes as a JSON array by default.

Components
- BeforeValidator(parse_comma_separated_list): Converts input strings to list[str]
  early in validation.
- PlainSerializer(serialize_list_of_strings, when_used="json"): Produces the "pycti"
  string form only for JSON serialization.

Examples
- Validation:
    from pydantic import BaseModel

    class Model(BaseModel):
        tags: ListFromString

    Model.model_validate({"tags": "a, b , c"}).tags  # -> ["a", "b", "c"]
    Model.model_validate({"tags": ["x", "y"]}).tags  # -> ["x", "y"]

- Serialization:
    m = Model.model_validate({"tags": ["e1", "e2"]})
    m.model_dump()                               # -> {'tags': ['e1', 'e2']}
    m.model_dump_json()                          # -> {"tags":["e1","e2"]}
    m.model_dump_json(context={"mode": "pycti"}) # -> {"tags":"e1,e2"}
""",
]


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
    """Annotated datetime that:
- Validates: Accepts an ISO-8601 string (datetime or duration).
  If a datetime ISO-8601 string is provided, and no timezone is present, the string
  is assumed to be UTC timezoned.
  If a duration ISO-8601 string is provided, the returned datetime will be relative
  to `datetime.now(timezone.utc)` at runtime.
- Serializes (JSON): Serializes a datetime object to an datetime ISO-8601 string.

Components
- BeforeValidator(parse_iso_string): Converts input strings to datetime
  early in validation.
- PlainSerializer(datetime.isoformat, when_used="json"): Produces the datetime ISO-8601 string
  for JSON serialization.

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
    m.model_dump_json(context={"mode": "pycti"}) # -> {"start_date": "2023-10-01T00:00:00+00:00"}
""",
]
