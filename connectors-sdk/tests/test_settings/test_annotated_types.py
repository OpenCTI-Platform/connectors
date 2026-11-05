import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import freezegun
import pytest
from connectors_sdk.settings.annotated_types import (
    ISO_DATETIME_OR_DURATION_PATTERN,
    DatetimeFromIsoString,
    ListFromString,
    parse_comma_separated_list,
    parse_iso_string,
)
from pydantic import BaseModel, Field, TypeAdapter, ValidationError

# ListFromString


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            "a,b,c",
            ["a", "b", "c"],
            id="comma_separated_list",
        ),
        pytest.param(
            "a, b  , c",
            ["a", "b", "c"],
            id="comma_separated_list_with_whitespaces",
        ),
        pytest.param(
            "",
            [],
            id="empty_string",  # empty string -> empty list
        ),
        pytest.param(
            "a, ,c",
            ["a", "c"],
            id="blank_item_between_commas",
        ),
        pytest.param(
            "a,,c",
            ["a", "c"],
            id="consecutive_commas",
        ),
        pytest.param(
            ",a,",
            ["a"],
            id="leading_and_trailing_commas",
        ),
    ],
)
def test_parse_comma_separated_list_handles_string(
    input: str, expected: list[str]
) -> None:
    assert parse_comma_separated_list(input) == expected


def test_parse_comma_separated_list_passthrough() -> None:
    assert parse_comma_separated_list(["a", "b"]) == ["a", "b"]


def test_list_from_string_accepts_string_input() -> None:
    value = TypeAdapter(ListFromString).validate_python("a,b,c")
    assert value == ["a", "b", "c"]


def test_list_from_string_accepts_list_input() -> None:
    value = TypeAdapter(ListFromString).validate_python(["a", "b"])
    assert value == ["a", "b"]


def test_list_from_string_discards_empty_items() -> None:
    value = TypeAdapter(ListFromString).validate_python("scope1, ,scope3")
    assert value == ["scope1", "scope3"]


def test_list_from_string_dumps_valid_json() -> None:
    value = TypeAdapter(ListFromString).dump_python(["a", "b"], mode="json")
    assert value == ["a", "b"]


# DatetimeFromIsoString


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            "2023-10-01",
            datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc),
            id="iso_date",
        ),
        pytest.param(
            "2023-10-01T12:30",
            datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc),
            id="iso_datetime",
        ),
        pytest.param(
            "2023-10-01T12:30+02:00",
            datetime(2023, 10, 1, 10, 30, tzinfo=timezone.utc),
            id="iso_datetime_with_timezone",
        ),
        pytest.param(
            "P30D",
            datetime(2023, 9, 1, 12, 30, tzinfo=timezone.utc),
            id="iso_duration",
        ),
        pytest.param(
            "PT5M",
            datetime(2023, 10, 1, 12, 25, tzinfo=timezone.utc),
            id="iso_time_duration",
        ),
    ],
)
@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_parse_iso_string_handles_string(input: str, expected: list[str]) -> None:
    assert parse_iso_string(input) == expected


def test_parse_iso_string_passthrough() -> None:
    assert parse_iso_string(
        datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc)
    ) == datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc)


def test_datetime_isoformat_handles_any_mode() -> None:
    value = datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)
    assert value.isoformat() == "2023-10-01T12:30:00+00:00"


def test_datetime_from_iso_string_accepts_string_input() -> None:
    value = TypeAdapter(DatetimeFromIsoString).validate_python("2023-10-01T12:30")
    assert value == datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)


def test_datetime_from_iso_string_accepts_datetime_input() -> None:
    value = TypeAdapter(DatetimeFromIsoString).validate_python(
        datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)
    )
    assert value == datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)


def test_datetime_from_iso_string_dumps_valid_json() -> None:
    value = TypeAdapter(DatetimeFromIsoString).dump_python(
        datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc), mode="json"
    )
    assert value == "2023-10-01T12:30:00+00:00"


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc),
            "2023-10-01T12:30:00+00:00",
            id="datetime",
        ),
        pytest.param(
            datetime(2023, 10, 1, 10, 30, tzinfo=timezone(timedelta(hours=2))),
            "2023-10-01T10:30:00+02:00",
            id="datetime_with_timezone",
        ),
    ],
)
def test_datetime_from_iso_string_dumps_valid_json_in_pycti_mode(
    input: list[str], expected: str
) -> None:
    value = TypeAdapter(DatetimeFromIsoString).dump_python(
        input, mode="json", context={"mode": "pycti"}
    )
    assert value == expected


def test_datetime_from_iso_string_json_schema_has_iso_pattern_without_format() -> None:
    schema = TypeAdapter(DatetimeFromIsoString).json_schema()

    assert schema == {"type": "string", "pattern": ISO_DATETIME_OR_DURATION_PATTERN}


VALID_ISO_VALUES = [
    # dates and datetimes
    "2023-10-01",
    "2024-02-29",  # leap year
    "2000-02-29",  # leap century
    "2023-10-01T12:30",
    "2023-10-01T12:30:00",
    "2023-10-01T12:30:00.123456",
    "2023-10-01T12:30:00Z",
    "2023-10-01T23:59:59Z",
    "2023-10-01T12:30:00+02:00",
    "2023-10-01T12:30:00-0530",
    "2023-10-01T12:30:00+02",
    "2023-10-01 12:30:00",
    "0002-01-01T00:00:00-23:59",
    "9998-12-31T23:59:59+23:59",
    # durations
    "P30D",
    "P1Y",
    "P4W",
    "PT5M",
    "P1Y2M3DT4H5M6S",
    "PT1.5S",
    "P999Y999M999W9999DT9999H9999M9999.999999S",  # longest accepted duration
]

INVALID_ISO_VALUES = [
    # invalid calendar values
    "2023-02-31",
    "2023-02-29",  # not a leap year
    "1900-02-29",  # not a leap century
    "2023-04-31",
    "2023-13-01",
    "2023-00-10",
    "2023-10-00",
    "0000-01-01",
    # invalid time values
    "2023-10-01T25:00:00Z",
    "2023-10-01T24:00:00Z",
    "2023-10-01T12:60:00Z",
    "2023-10-01T12:30:60Z",
    "2023-10-01T12:30:00+24:00",
    "2023-10-01T12:30:00+02:60",
    # datetimes that cannot be converted to UTC
    "0001-01-01T00:00:00+02:00",
    "9999-12-31T23:59:59-02:00",
    # basic and other non-extended formats, not accepted by the schema
    "20231001",
    "20231001T123000Z",
    "2023-W40-7",
    "2023-274",
    "2023-10-01t12:30:00Z",
    "2023-10-01T12:30:00z",
    "2023-10",
    "2023/10/01",
    # invalid durations
    "",
    "P",
    "PT",
    "P1DT",
    "P1H",
    "PT1D",
    "P1D2H",
    "P-1D",
    "-P1D",
    "P1.5D",
    "P1,5D",
    "p30d",
    "P1000Y",
    "P99999999999D",
    "30D",
    # numeric and timedelta-like strings
    "3600",
    "1.5",
    "00:30:00",
    "1 day",
    # regex-engine differences between Python and ECMAScript
    "2023-10-01\n",
    "P30D\n",
    "\uff12\uff10\uff12\uff13-10-01",
    "yesterday",
]


def _schema_accepts(value: str) -> bool:
    # `fullmatch` + `re.ASCII` mirror how AJV evaluates the pattern (`u` flag)
    return re.fullmatch(ISO_DATETIME_OR_DURATION_PATTERN, value, re.ASCII) is not None


def _parses(value: str) -> bool:
    try:
        parse_iso_string(value)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("value", VALID_ISO_VALUES)
@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_iso_values_accepted_by_both_schema_and_parser(value: str) -> None:
    assert _schema_accepts(value)
    assert isinstance(parse_iso_string(value), datetime)
    assert isinstance(
        TypeAdapter(DatetimeFromIsoString).validate_python(value), datetime
    )


@pytest.mark.parametrize("value", INVALID_ISO_VALUES)
@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_iso_values_rejected_by_both_schema_and_parser(value: str) -> None:
    assert not _schema_accepts(value)
    with pytest.raises(ValueError):
        parse_iso_string(value)
    with pytest.raises(ValidationError):
        TypeAdapter(DatetimeFromIsoString).validate_python(value)


@pytest.mark.parametrize(
    "input,expected",
    [
        ("2023-10-01", datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc)),
        ("2024-02-29", datetime(2024, 2, 29, 0, 0, tzinfo=timezone.utc)),
        ("2023-10-01T12:30:00Z", datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)),
        (
            "2023-10-01T12:30:00-0530",
            datetime(2023, 10, 1, 18, 0, tzinfo=timezone.utc),
        ),
        ("P1Y", datetime(2022, 10, 1, 12, 30, tzinfo=timezone.utc)),  # 365 days
        ("P1M", datetime(2023, 9, 1, 12, 30, tzinfo=timezone.utc)),  # 30 days
        ("P1W", datetime(2023, 9, 24, 12, 30, tzinfo=timezone.utc)),
        ("P1DT1H", datetime(2023, 9, 30, 11, 30, tzinfo=timezone.utc)),
    ],
)
@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_parse_iso_string_returns_expected_utc_datetime(
    input: str, expected: datetime
) -> None:
    assert parse_iso_string(input) == expected


def test_parse_iso_string_rejects_basic_format_with_explicit_error() -> None:
    with pytest.raises(ValueError, match="Invalid ISO-8601 datetime or duration"):
        parse_iso_string("20231001")


def test_iso_pattern_is_calendar_exact() -> None:
    """The pattern must accept a date if and only if `datetime.fromisoformat` does."""
    years = [2, 4, 1900, 1904, 2000, 2023, 2024, 2100, 2400, 9996, 9998]
    for year in years:
        for month in range(0, 14):
            for day in range(0, 33):
                value = f"{year:04d}-{month:02d}-{day:02d}"
                try:
                    datetime.fromisoformat(value)
                    expected = True
                except ValueError:
                    expected = False
                assert _schema_accepts(value) is expected, value


def test_iso_pattern_is_time_exact() -> None:
    """The pattern must accept a time and offset if and only if the runtime does."""
    time_values = [
        f"2023-10-01T{hour:02d}:{minute:02d}:{second:02d}"
        for hour in (0, 12, 23, 24, 25, 99)
        for minute in (0, 30, 59, 60, 99)
        for second in (0, 30, 59, 60, 99)
    ]
    offsets = ["", "Z"] + [
        f"{sign}{hour:02d}:{minute:02d}"
        for sign in "+-"
        for hour in (0, 2, 23, 24, 99)
        for minute in (0, 30, 59, 60, 99)
    ]
    for time_value in time_values:
        for offset in offsets:
            value = f"{time_value}{offset}"
            try:
                datetime.fromisoformat(value).astimezone(timezone.utc)
                # `fromisoformat` is lenient on offset minutes (e.g. "+00:60"), which
                # are not valid ISO-8601: the pattern is deliberately stricter here
                expected = not offset.endswith(("60", "99"))
            except ValueError:
                expected = False
            assert _schema_accepts(value) is expected, value


@pytest.mark.parametrize(
    "value",
    ["P1000Y", "P1000M", "P1000W", "P10000D", "PT10000H", "PT10000M", "PT10000S"],
)
def test_iso_pattern_rejects_durations_that_could_overflow(value: str) -> None:
    assert not _schema_accepts(value)


def test_iso_pattern_is_valid_ecmascript_regex() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")
    script = "new RegExp(process.argv[1], 'u')"
    result = subprocess.run(  # noqa: S603
        [node, "-e", script, ISO_DATETIME_OR_DURATION_PATTERN],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_datetime_from_iso_string_duration_default_is_kept_in_json_schema() -> None:
    class Model(BaseModel):
        start_date: DatetimeFromIsoString = Field(default="P30D", validate_default=True)

    schema = Model.model_json_schema()["properties"]["start_date"]

    assert schema["default"] == "P30D"
    assert Model().start_date == datetime(2023, 9, 1, 12, 30, tzinfo=timezone.utc)
