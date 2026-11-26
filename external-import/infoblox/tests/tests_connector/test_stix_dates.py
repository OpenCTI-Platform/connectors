"""Regression tests for the TIDE `detected` / `imported` timestamp handling."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector import Infoblox
from connector.connector import InvalidTimestampError, parse_tide_timestamp
from connectors_sdk.exceptions.error import UseCaseError
from pycti import Indicator

IDENTITY_ID = "identity--2998978f-8336-5dfc-93a2-2f3d2f79d0e3"


@pytest.fixture
def connector() -> Infoblox:
    """Infoblox connector built with a mocked config and a mocked helper."""
    config = MagicMock()
    config.infoblox.marking_definition = "TLP:AMBER+STRICT"
    helper = MagicMock()
    return Infoblox(config=config, helper=helper)


def make_ip_threat(detected, imported, ip="203.0.113.10") -> dict:
    """Build a TIDE IP threat record."""
    return {
        "id": f"id-{ip}",
        "type": "IP",
        "ip": ip,
        "threat_level": 80,
        "confidence": 90,
        "class": "Malware",
        "property": "MalwareC2",
        "extended": {"notes": "some notes"},
        "detected": detected,
        "imported": imported,
    }


def make_url_threat(detected, imported, url="http://bad.example.com/a") -> dict:
    """Build a TIDE URL threat record."""
    return {
        "id": f"id-{url}",
        "type": "URL",
        "url": url,
        "threat_level": 70,
        "confidence": 85,
        "class": "Phishing",
        "property": "PhishingGeneric",
        "extended": {"notes": "other notes"},
        "detected": detected,
        "imported": imported,
    }


def indicators_of(bundle) -> list:
    """Return the indicators of a bundle, in order."""
    return [obj for obj in bundle.objects if obj["type"] == "indicator"]


def utc(*args) -> datetime:
    """Build a timezone-aware UTC datetime."""
    return datetime(*args, tzinfo=timezone.utc)


def test_milliseconds_timestamps_keep_their_values_and_serialization(connector):
    """#5355: the format that already worked (`.392Z`) is parsed and serialized as before."""
    threat = make_ip_threat("2024-05-01T10:20:21.392Z", "2024-05-02T11:21:22.123Z")

    bundle, _ = connector.create_stix_bundle("", {"threat": [threat]}, "")

    (indicator,) = indicators_of(bundle)
    assert indicator.created == utc(2024, 5, 1, 10, 20, 21, 392000)
    assert indicator.modified == utc(2024, 5, 2, 11, 21, 22, 123000)
    serialized = json.loads(bundle.serialize())
    serialized_indicator = next(
        o for o in serialized["objects"] if o["type"] == "indicator"
    )
    assert serialized_indicator["created"] == "2024-05-01T10:20:21.392Z"
    assert serialized_indicator["modified"] == "2024-05-02T11:21:22.123Z"


def test_timestamps_without_fractional_seconds_are_parsed(connector):
    """#5355: `2024-05-01T10:20:48Z` (no fractional seconds) must not abort the bundle."""
    threat = make_ip_threat("2024-05-01T10:20:48Z", "2024-05-02T11:21:49Z")

    bundle, _ = connector.create_stix_bundle("", {"threat": [threat]}, "")

    (indicator,) = indicators_of(bundle)
    assert indicator.created == utc(2024, 5, 1, 10, 20, 48)
    assert indicator.modified == utc(2024, 5, 2, 11, 21, 49)
    serialized = json.loads(bundle.serialize())
    serialized_indicator = next(
        o for o in serialized["objects"] if o["type"] == "indicator"
    )
    assert serialized_indicator["created"] == "2024-05-01T10:20:48.000Z"


@pytest.mark.parametrize(
    "raw, expected",
    [
        pytest.param(
            "2024-05-01T10:20:21.652226Z",
            utc(2024, 5, 1, 10, 20, 21, 652226),
            id="microseconds",
        ),
        pytest.param(
            "2024-05-01T10:20:21.6522261Z",
            utc(2024, 5, 1, 10, 20, 21, 652226),
            id="seven-fractional-digits-truncated",
        ),
        pytest.param(
            "2024-05-01T10:20:21+00:00",
            utc(2024, 5, 1, 10, 20, 21),
            id="utc-offset",
        ),
        pytest.param(
            "2024-05-01T10:20:21+02:00",
            utc(2024, 5, 1, 8, 20, 21),
            id="positive-offset-converted-to-utc",
        ),
        pytest.param(
            "2024-05-01T10:20:21",
            utc(2024, 5, 1, 10, 20, 21),
            id="naive-assumed-utc",
        ),
    ],
)
def test_timestamp_variants_are_parsed_to_timezone_aware_utc(connector, raw, expected):
    """#5355: microseconds, explicit offsets and naive strings parse to aware UTC."""
    threat = make_url_threat(raw, raw)

    bundle, _ = connector.create_stix_bundle({"threat": [threat]}, "", "")

    (indicator,) = indicators_of(bundle)
    assert indicator.created == expected
    assert indicator.modified == expected
    assert indicator.created.utcoffset().total_seconds() == 0
    assert indicator.modified.utcoffset().total_seconds() == 0


def test_mixed_timestamp_formats_in_one_bundle_are_all_kept(connector):
    """#5355: one record with another date format must not drop the rest of the bundle."""
    ips = [
        make_ip_threat("2024-05-01T10:20:21.392Z", "2024-05-01T10:20:21.392Z"),
        make_ip_threat(
            "2024-05-01T10:20:48Z", "2024-05-01T10:20:48Z", ip="203.0.113.11"
        ),
    ]
    urls = [
        make_url_threat("2024-05-01T12:20:21+02:00", "2024-05-01T12:20:21+02:00"),
    ]

    bundle, all_threats = connector.create_stix_bundle(
        {"threat": urls}, {"threat": ips}, ""
    )

    assert len(all_threats) == 3
    created = sorted(indicator.created for indicator in indicators_of(bundle))
    assert created == [
        utc(2024, 5, 1, 10, 20, 21),
        utc(2024, 5, 1, 10, 20, 21, 392000),
        utc(2024, 5, 1, 10, 20, 48),
    ]
    assert len([o for o in bundle.objects if o["type"] == "relationship"]) == 3


@pytest.mark.parametrize(
    "bad_fields",
    [
        pytest.param({"detected": "not-a-date"}, id="unparseable-detected"),
        pytest.param({"imported": "yesterday"}, id="unparseable-imported"),
        pytest.param({"detected": None}, id="null-detected"),
        pytest.param({"detected": "__missing__"}, id="missing-detected"),
    ],
)
def test_threat_with_bad_date_is_skipped_with_one_warning(connector, bad_fields):
    """#5355: a record with a bad or missing date is skipped, the others are sent."""
    bad = make_ip_threat(
        "2024-05-01T10:20:21.392Z", "2024-05-01T10:20:21.392Z", ip="203.0.113.99"
    )
    for key, value in bad_fields.items():
        if value == "__missing__":
            del bad[key]
        else:
            bad[key] = value
    good = make_url_threat("2024-05-01T10:20:48.123Z", "2024-05-01T10:20:48.123Z")

    bundle, _ = connector.create_stix_bundle({"threat": [good]}, {"threat": [bad]}, "")

    indicators = indicators_of(bundle)
    assert [i.name for i in indicators] == ["http://bad.example.com/a"]
    warning = connector.helper.connector_logger.warning
    assert warning.call_count == 1
    message, context = warning.call_args.args
    assert message == "Skipping Infoblox threat with an invalid timestamp"
    assert context["threat_id"] == "id-203.0.113.99"
    assert context["type"] == "IP"
    assert context["error"]
    assert context["cause"]
    assert set(context) == {"threat_id", "type", "error", "cause"}
    object_ids = {o.id for o in bundle.objects}
    assert IDENTITY_ID in object_ids
    assert connector.marking.id in object_ids
    assert not [o for o in bundle.objects if o.get("value") == "203.0.113.99"]


def test_non_date_conversion_error_is_not_swallowed(connector):
    """#5355: only timestamp failures are skipped, other conversion errors propagate."""
    threat = make_ip_threat("2024-05-01T10:20:21.392Z", "2024-05-01T10:20:21.392Z")
    del threat["ip"]

    with pytest.raises(KeyError):
        connector.create_stix_bundle("", {"threat": [threat]}, "")

    connector.helper.connector_logger.warning.assert_not_called()


def test_non_date_value_error_is_not_swallowed(connector, monkeypatch):
    """#5355: a plain ValueError that is not about dates is re-raised, not skipped."""
    threat = make_ip_threat("2024-05-01T10:20:21.392Z", "2024-05-01T10:20:21.392Z")

    def boom(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(connector, "create_stix_object", boom)

    with pytest.raises(ValueError, match="boom"):
        connector.create_stix_bundle("", {"threat": [threat]}, "")

    connector.helper.connector_logger.warning.assert_not_called()


def test_invalid_timestamp_error_is_a_use_case_error():
    """#5355: InvalidTimestampError is an SDK UseCaseError and still a ValueError."""
    assert issubclass(InvalidTimestampError, UseCaseError)
    assert issubclass(InvalidTimestampError, ValueError)


@pytest.mark.parametrize(
    "value, cause_type",
    [
        pytest.param(None, TypeError, id="none"),
        pytest.param("not-a-date", ValueError, id="unparseable"),
        pytest.param(
            "0001-01-01T00:00:00+01:00", OverflowError, id="utc-conversion-underflow"
        ),
        pytest.param(
            "9999-12-31T23:59:59-01:00", OverflowError, id="utc-conversion-overflow"
        ),
    ],
)
def test_parse_tide_timestamp_raises_invalid_timestamp_error(value, cause_type):
    """#5355: a missing, unparseable or out-of-range timestamp raises a chained InvalidTimestampError."""
    with pytest.raises(InvalidTimestampError) as err:
        parse_tide_timestamp(value)

    assert isinstance(err.value, ValueError)
    assert str(err.value) == f"Invalid TIDE timestamp: {value!r}"
    assert isinstance(err.value.__cause__, (TypeError, ValueError, OverflowError))
    assert type(err.value.__cause__) is cause_type


def test_indicator_ids_do_not_depend_on_the_date_format(connector):
    """#5355: the indicator id comes from the pattern only, whatever the date format."""
    ms = make_ip_threat("2024-05-01T10:20:21.392Z", "2024-05-01T10:20:21.392Z")
    no_fraction = make_ip_threat("2024-05-09T01:02:03Z", "2024-05-09T01:02:03Z")
    offset = make_ip_threat("2024-05-09T03:02:03+02:00", "2024-05-09T03:02:03+02:00")

    ids = []
    for threat in (ms, no_fraction, offset):
        bundle, _ = connector.create_stix_bundle("", {"threat": [threat]}, "")
        (indicator,) = indicators_of(bundle)
        ids.append(indicator.id)

    assert ids == [Indicator.generate_id("[ipv4-addr:value = '203.0.113.10']")] * 3
