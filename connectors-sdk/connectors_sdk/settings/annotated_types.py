"""Commonly used Pydantic types with custom validation and serialization logic."""

import re
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
#
# This pattern is the single source of truth of the accepted grammar: `parse_iso_string`
# rejects anything it does not match, and everything it matches is parseable. It is
# therefore deliberately stricter than `datetime.fromisoformat` and pydantic's timedelta
# parser, which also accept basic formats (`20231001`), week/ordinal dates, lowercase
# `t`/`p`, numeric seconds (`"3600"`), `-P1D`, `P1,5D`, etc.
#
# Datetime: extended format only, calendar-exact (month lengths, leap years, 00-23h,
# 00-59min/s, offsets up to +/-23:59). Years 0000, 0001 and 9999 are excluded so that
# the conversion to UTC can never overflow `datetime`.
#
# Duration: `PnYnMnWnDTnHnMnS` in this order, each designator optional but at least one
# value (and one time value after `T`), integers except for a decimal fraction on
# seconds. Number of digits is capped (`Y`, `M`, `W`: 3, others: 4) so the longest
# accepted duration (~1,130 years) can always be subtracted from the current date.
_HOUR = r"(?:[01]\d|2[0-3])"
_MINUTE_OR_SECOND = r"[0-5]\d"
_LEAP_YEAR = r"(?:\d\d(?:0[48]|[2468][048]|[13579][26])|(?:[02468][048]|[13579][26])00)"
ISO_DATETIME_PATTERN = (
    r"(?!0000|0001|9999)(?:"
    r"\d{4}-(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])"
    r"|\d{4}-(?:0[469]|11)-(?:0[1-9]|[12]\d|30)"
    r"|\d{4}-02-(?:0[1-9]|1\d|2[0-8])"
    rf"|{_LEAP_YEAR}-02-29"
    r")"
    rf"(?:[T ]{_HOUR}:{_MINUTE_OR_SECOND}"
    rf"(?::{_MINUTE_OR_SECOND}(?:\.\d+)?)?"
    rf"(?:Z|[+-]{_HOUR}(?::?{_MINUTE_OR_SECOND})?)?)?"
)
ISO_DURATION_PATTERN = (
    r"P(?!$)(?:\d{1,3}Y)?(?:\d{1,3}M)?(?:\d{1,3}W)?(?:\d{1,4}D)?"
    r"(?:T(?=\d)(?:\d{1,4}H)?(?:\d{1,4}M)?(?:\d{1,4}(?:\.\d+)?S)?)?"
)
ISO_DATETIME_OR_DURATION_PATTERN = (
    rf"^(?:{ISO_DATETIME_PATTERN}|{ISO_DURATION_PATTERN})$"
)

# `re.ASCII` and `fullmatch` mirror ECMAScript semantics: `\d` only matches 0-9 (not
# other Unicode digits) and `$` does not match before a trailing newline.
_ISO_DATETIME_REGEX = re.compile(ISO_DATETIME_PATTERN, re.ASCII)
_ISO_DURATION_REGEX = re.compile(ISO_DURATION_PATTERN, re.ASCII)


def parse_iso_string(value: str | datetime) -> datetime:
    """Convert ISO string into a datetime object.

    Only strings matching `ISO_DATETIME_OR_DURATION_PATTERN` (the pattern advertised in
    the JSON schema) are accepted, anything else raises a `ValueError`.

    Example:
        > value = parse_iso_string("2023-10-01T00:00:00Z")
        > print(value) # 2023-10-01 00:00:00+00:00

        # If today is 2023-10-01:
        > value = parse_iso_string("P30D")
        > print(value) # 2023-09-01 00:00:00+00:00

    Note:
        As in pydantic's timedelta parsing, a year lasts 365 days and a month 30 days
        in a duration.
    """
    if not isinstance(value, str):
        return value

    if _ISO_DATETIME_REGEX.fullmatch(value):
        parsed_datetime = datetime.fromisoformat(value)
        if parsed_datetime.tzinfo:
            return parsed_datetime.astimezone(tz=timezone.utc)
        return parsed_datetime.replace(tzinfo=timezone.utc)

    if _ISO_DURATION_REGEX.fullmatch(value):
        duration = TypeAdapter(timedelta).validate_python(value)
        return datetime.now(timezone.utc) - duration

    raise ValueError(
        f"Invalid ISO-8601 datetime or duration: {value!r}. "
        "Expected e.g. '2023-10-01', '2023-10-01T12:30:00Z' or 'P30D'."
    )


DatetimeFromIsoString = Annotated[
    datetime,
    BeforeValidator(parse_iso_string),
    # Replace the default JSON serializer, in order to use +00:00 offset instead of Z prefix
    PlainSerializer(datetime.isoformat, when_used="json"),
    # Advertise both ISO-8601 datetimes and durations in the JSON schema, as OpenCTI
    # validates managed connectors config against it (a `format` accepts only one)
    WithJsonSchema({"type": "string", "pattern": ISO_DATETIME_OR_DURATION_PATTERN}),
    """Annotated datetime that:
- Validates: Accepts an ISO-8601 string (datetime or duration) matching
  `ISO_DATETIME_OR_DURATION_PATTERN`, i.e. the extended datetime format (basic format
  such as `20231001` is rejected) or a `PnYnMnWnDTnHnMnS` duration. Invalid calendar
  values (e.g. `2023-02-31`, `T25:00`) are rejected.
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
