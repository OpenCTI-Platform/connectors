# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Tests of the deployment write-back helpers."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from connectors_sdk.connectors.stream.deployment.utils import (
    OPENCTI_EXTENSION_ID,
    PatternValue,
    deployment_failure_reason,
    extract_pattern_values,
    format_datetime,
    get_opencti_extension,
    get_opencti_indicator_id,
    is_stix_indicator,
    normalize_value,
    parse_datetime,
    pattern_observable_values,
    to_stream_indicator,
)


def test_get_opencti_extension_returns_the_extension_content():
    """The OpenCTI extension of a stream object is returned."""
    stix_object = {"extensions": {OPENCTI_EXTENSION_ID: {"id": "internal-id"}}}
    assert get_opencti_extension(stix_object) == {"id": "internal-id"}


@pytest.mark.parametrize(
    "stix_object",
    [
        {},
        {"extensions": None},
        {"extensions": []},
        {"extensions": {OPENCTI_EXTENSION_ID: "not a mapping"}},
        {"extensions": {"extension-definition--other": {"id": "x"}}},
    ],
)
def test_get_opencti_extension_returns_empty_mapping_when_absent(stix_object):
    """Objects without a valid OpenCTI extension give an empty mapping."""
    assert get_opencti_extension(stix_object) == {}


def test_is_stix_indicator():
    """Only STIX indicators are recognized."""
    assert is_stix_indicator({"type": "indicator"})
    assert not is_stix_indicator({"type": "ipv4-addr"})
    assert not is_stix_indicator({})


def test_get_opencti_indicator_id_prefers_the_internal_id():
    """The internal id of the OpenCTI extension is preferred over the STIX id."""
    stix_object = {
        "id": "indicator--1",
        "extensions": {OPENCTI_EXTENSION_ID: {"id": "internal-id"}},
    }
    assert get_opencti_indicator_id(stix_object) == "internal-id"


def test_get_opencti_indicator_id_falls_back_to_the_stix_id():
    """The STIX id is used when no internal id is available."""
    stix_object = {
        "id": "indicator--1",
        "extensions": {OPENCTI_EXTENSION_ID: {"id": ""}},
    }
    assert get_opencti_indicator_id(stix_object) == "indicator--1"


@pytest.mark.parametrize("stix_object", [{}, {"id": ""}, {"id": 42}])
def test_get_opencti_indicator_id_returns_none_without_identifier(stix_object):
    """No identifier gives ``None``."""
    assert get_opencti_indicator_id(stix_object) is None


@pytest.mark.parametrize(
    "status_code, expected",
    [
        (400, "Cortex XDR refused the IOC upsert: invalid request"),
        (401, "Cortex XDR refused the IOC upsert: authentication failed"),
        (403, "Cortex XDR refused the IOC upsert: permission denied"),
        (404, "Cortex XDR refused the IOC upsert: not found"),
        (409, "Cortex XDR refused the IOC upsert: conflict with an existing item"),
        (413, "Cortex XDR refused the IOC upsert: request too large"),
        (422, "Cortex XDR refused the IOC upsert: invalid request"),
        (429, "Cortex XDR refused the IOC upsert: rate limit reached"),
        (500, "Cortex XDR refused the IOC upsert: server error"),
        (503, "Cortex XDR refused the IOC upsert: server error"),
        (418, "Cortex XDR refused the IOC upsert: unexpected response"),
        (200, "Cortex XDR returned an unexpected response to the IOC upsert"),
        (None, "Cortex XDR could not be reached for the IOC upsert"),
    ],
)
def test_deployment_failure_reason(status_code, expected):
    assert deployment_failure_reason("Cortex XDR", "IOC upsert", status_code) == (
        expected
    )


def test_extract_pattern_values_parses_equality_comparisons():
    """Equality comparisons are extracted with their type, path and unescaped value."""
    pattern = (
        "[ipv4-addr:value = '198.51.100.7' OR domain-name:value='evil.example'] AND "
        "[file:hashes.'SHA-256' = 'abc' AND url:value = 'http://x.example/it\\'s']"
    )
    assert extract_pattern_values(pattern) == [
        PatternValue("ipv4-addr", "value", "198.51.100.7"),
        PatternValue("domain-name", "value", "evil.example"),
        PatternValue("file", "hashes.'SHA-256'", "abc"),
        PatternValue("url", "value", "http://x.example/it's"),
    ]


def test_extract_pattern_values_unescapes_backslashes():
    """Escaped backslashes are unescaped."""
    pattern = "[windows-registry-key:key = 'HKLM\\\\Software']"
    assert extract_pattern_values(pattern)[0].value == "HKLM\\Software"


@pytest.mark.parametrize("pattern", [None, "", "[ipv4-addr:value LIKE '10.%']"])
def test_extract_pattern_values_returns_empty_list_without_equality(pattern):
    """Patterns without an equality comparison give no value."""
    assert extract_pattern_values(pattern) == []


def test_pattern_value_hash_algorithm():
    """The hash algorithm is only given for file hashes comparisons."""
    assert PatternValue("file", "hashes.'SHA-256'", "a").hash_algorithm == "SHA-256"
    assert PatternValue("file", "hashes.MD5", "a").hash_algorithm == "MD5"
    assert PatternValue("file", "name", "a").hash_algorithm is None
    assert PatternValue("url", "value", "a").hash_algorithm is None


def test_pattern_observable_values_builds_stream_observable_values():
    """Observable values merge file hashes and skip unknown types."""
    pattern = (
        "[ipv4-addr:value = '198.51.100.7'] OR [file:hashes.MD5 = 'aa' OR "
        "file:hashes.'SHA-256' = 'bb'] OR [x-custom:value = 'ignored'] OR "
        "[file:name = 'ignored.exe']"
    )
    assert pattern_observable_values(pattern) == [
        {"type": "IPv4-Addr", "value": "198.51.100.7"},
        {"type": "StixFile", "hashes": {"MD5": "aa", "SHA-256": "bb"}},
    ]


def test_pattern_observable_values_without_file_hashes():
    """No ``StixFile`` entry is added without hashes."""
    assert pattern_observable_values("[url:value = 'http://x.example']") == [
        {"type": "Url", "value": "http://x.example"}
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        (" Evil.Example ", "evil.example"),
        (42, "42"),
        ("HTTPS://Evil.Example/Admin?Id=A#Top", "https://evil.example/Admin?Id=A#Top"),
        ("http://Evil.Example", "http://evil.example"),
        ("http://Evil.Example?Q=1", "http://evil.example?Q=1"),
        (
            "HTTPS://User:Secret@Evil.Example:8443/X",
            "https://User:Secret@evil.example:8443/X",
        ),
        ("ftp://Us@er@Evil.Example", "ftp://Us@er@evil.example"),
    ],
)
def test_normalize_value(value, expected):
    """Values are stripped and lower-cased except URL paths, empty ones give ``None``."""
    assert normalize_value(value) == expected


def test_normalize_value_keeps_url_paths_apart():
    """URLs differing only by the case of their path are two observables."""
    assert normalize_value("http://evil.example/Admin") != normalize_value(
        "http://evil.example/admin"
    )


def test_parse_datetime_accepts_datetimes_and_iso_strings():
    """Datetimes and ISO strings give timezone-aware datetimes."""
    aware = datetime(2026, 10, 3, 10, 0, tzinfo=timezone(timedelta(hours=2)))
    assert parse_datetime(aware) is aware
    assert parse_datetime(datetime(2026, 10, 3, 10, 0)) == datetime(
        2026, 10, 3, 10, 0, tzinfo=UTC
    )
    assert parse_datetime("2026-10-03T10:00:00Z") == datetime(
        2026, 10, 3, 10, 0, tzinfo=UTC
    )
    assert parse_datetime("2026-10-03T10:00:00") == datetime(
        2026, 10, 3, 10, 0, tzinfo=UTC
    )


@pytest.mark.parametrize("value", [None, "", "  ", "not a date"])
def test_parse_datetime_returns_none_for_empty_or_invalid_values(value):
    """Empty or invalid values give ``None``."""
    assert parse_datetime(value) is None


def test_format_datetime():
    """Dates are formatted as ISO 8601 UTC strings with a ``Z`` suffix."""
    assert format_datetime(None) is None
    assert format_datetime("") is None
    assert format_datetime("not a date") == "not a date"
    assert (
        format_datetime(
            datetime(2026, 10, 3, 12, 0, tzinfo=timezone(timedelta(hours=2)))
        )
        == "2026-10-03T10:00:00.000Z"
    )
    assert format_datetime("2026-10-03T10:00:00+00:00") == "2026-10-03T10:00:00.000Z"


def test_to_stream_indicator_moves_opencti_attributes_into_the_extension():
    """The export shape is converted into the stream event shape."""
    exported = {
        "type": "indicator",
        "id": "indicator--1",
        "pattern": "[domain-name:value = 'evil.example']",
        "pattern_type": "stix",
        "x_opencti_score": 80,
        "x_opencti_main_observable_type": "Domain-Name",
        "x_opencti_id": "internal-id",
        "extensions": {"extension-definition--other": {"x": 1}},
    }

    stream_indicator = to_stream_indicator(exported, "fallback-id")

    assert "x_opencti_score" not in stream_indicator
    assert stream_indicator["extensions"]["extension-definition--other"] == {"x": 1}
    assert stream_indicator["extensions"][OPENCTI_EXTENSION_ID] == {
        "score": 80,
        "main_observable_type": "Domain-Name",
        "id": "internal-id",
        "extension_type": "property-extension",
        "type": "Indicator",
        "observable_values": [{"type": "Domain-Name", "value": "evil.example"}],
    }
    assert get_opencti_indicator_id(stream_indicator) == "internal-id"


def test_to_stream_indicator_keeps_an_existing_extension():
    """An existing OpenCTI extension is kept and completed."""
    exported = {
        "type": "indicator",
        "id": "indicator--1",
        "pattern": "[x-custom:value = 'no observable']",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": "internal-id",
                "observable_values": [{"type": "Url", "value": "http://x.example"}],
            }
        },
    }

    extension = to_stream_indicator(exported, "fallback-id")["extensions"][
        OPENCTI_EXTENSION_ID
    ]

    assert extension["id"] == "internal-id"
    assert extension["observable_values"] == [
        {"type": "Url", "value": "http://x.example"}
    ]


def test_to_stream_indicator_without_observable_values():
    """No observable values are added for patterns without supported values."""
    exported = {"type": "indicator", "id": "indicator--1", "pattern": "rule yara {}"}

    extension = to_stream_indicator(exported, "internal-id")["extensions"][
        OPENCTI_EXTENSION_ID
    ]

    assert extension["id"] == "internal-id"
    assert "observable_values" not in extension
