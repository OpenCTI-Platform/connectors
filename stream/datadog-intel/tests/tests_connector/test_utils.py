from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from connector.utils import (
    STIX_TYPE_TO_INDICATOR_TYPE,
    indicator_id_from_event,
    indicator_type_for_event,
    is_valid_event,
    main_observable_type_from_event,
    normalize_event_type,
)

# ---------------------------------------------------------------------------
# main_observable_type_from_event
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data, expected",
    [
        pytest.param(
            {"extensions": {"ext-1": {"main_observable_type": "IPv4-Addr"}}},
            "IPv4-Addr",
            id="returns_first_main_observable_type",
        ),
        pytest.param(
            {"extensions": {}},
            None,
            id="empty_extensions_returns_none",
        ),
        pytest.param(
            {},
            None,
            id="no_extensions_key_returns_none",
        ),
        pytest.param(
            {"extensions": None},
            None,
            id="null_extensions_returns_none",
        ),
        pytest.param(
            {"extensions": "not-a-dict"},
            None,
            id="non_dict_extensions_returns_none",
        ),
        pytest.param(
            {"extensions": {"ext-1": {"other_field": "value"}}},
            None,
            id="extension_without_main_observable_type_returns_none",
        ),
        pytest.param(
            {"extensions": {"ext-1": "not-a-dict"}},
            None,
            id="non_dict_extension_value_returns_none",
        ),
    ],
)
def test_main_observable_type_from_event(data, expected):
    assert main_observable_type_from_event(data) == expected


# ---------------------------------------------------------------------------
# indicator_id_from_event
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data, expected",
    [
        pytest.param(
            {"extensions": {"ext-1": {"id": "indicator--abc123"}}},
            "indicator--abc123",
            id="returns_first_id",
        ),
        pytest.param(
            {"extensions": {}},
            None,
            id="empty_extensions_returns_none",
        ),
        pytest.param(
            {},
            None,
            id="no_extensions_key_returns_none",
        ),
        pytest.param(
            {"extensions": None},
            None,
            id="null_extensions_returns_none",
        ),
        pytest.param(
            {"extensions": "not-a-dict"},
            None,
            id="non_dict_extensions_returns_none",
        ),
        pytest.param(
            {"extensions": {"ext-1": {"other_field": "value"}}},
            None,
            id="extension_without_id_returns_none",
        ),
    ],
)
def test_indicator_id_from_event(data, expected):
    assert indicator_id_from_event(data) == expected


# ---------------------------------------------------------------------------
# normalize_event_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data, expected",
    [
        pytest.param({"event_type": "create"}, "create", id="create_passthrough"),
        pytest.param({"event_type": "update"}, "update", id="update_passthrough"),
        pytest.param({"event_type": "delete"}, "delete", id="delete_passthrough"),
        pytest.param(
            {"event_type": "message"}, "create", id="message_mapped_to_create"
        ),
        pytest.param({}, "create", id="missing_event_type_mapped_to_create"),
        pytest.param(
            {"event_type": None}, "create", id="null_event_type_mapped_to_create"
        ),
        pytest.param(
            {"event_type": ""}, "create", id="empty_event_type_mapped_to_create"
        ),
    ],
)
def test_normalize_event_type(data, expected):
    assert normalize_event_type(data) == expected


# ---------------------------------------------------------------------------
# is_valid_event
# ---------------------------------------------------------------------------


def _make_helper():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return helper


def _make_config(indicator_type=None):
    config = MagicMock()
    config.datadog_intel.indicator_type = (
        indicator_type if indicator_type is not None else ["ip_address"]
    )
    return config


def _future_timestamp():
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def _past_timestamp():
    return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


def _base_event(**overrides):
    event = {
        "type": "indicator",
        "pattern_type": "stix",
        "extensions": {"ext-1": {"main_observable_type": "IPv4-Addr"}},
        "valid_until": _future_timestamp(),
    }
    event.update(overrides)
    return event


@pytest.mark.parametrize(
    "indicator_type, observable_type",
    [
        pytest.param(["ip_address"], "IPv4-Addr", id="ip_address_IPv4"),
        pytest.param(["ip_address"], "IPv6-Addr", id="ip_address_IPv6"),
        pytest.param(["domain"], "Domain-Name", id="domain"),
        pytest.param(["sha256"], "StixFile", id="sha256"),
        pytest.param(["ip_address", "domain"], "Domain-Name", id="multi_type_domain"),
        pytest.param(["ip_address", "domain"], "IPv4-Addr", id="multi_type_ip"),
    ],
)
def test_is_valid_event_returns_true_for_allowed_types(indicator_type, observable_type):
    event = _base_event(extensions={"ext-1": {"main_observable_type": observable_type}})
    assert is_valid_event(event, _make_helper(), _make_config(indicator_type)) is True


@pytest.mark.parametrize(
    "event_type",
    ["create", "update", "delete"],
)
def test_is_valid_event_accepts_all_recognized_event_types(event_type):
    event = _base_event(event_type=event_type)
    assert is_valid_event(event, _make_helper(), _make_config()) is True


def test_is_valid_event_accepts_initial_load_message():
    event = _base_event()
    del event["valid_until"]
    event["event_type"] = "message"
    assert is_valid_event(event, _make_helper(), _make_config()) is True


def test_is_valid_event_rejects_non_indicator_entity_type():
    event = _base_event(type="observed-data")
    assert is_valid_event(event, _make_helper(), _make_config()) is False


def test_is_valid_event_rejects_non_stix_pattern_type():
    event = _base_event(pattern_type="pcre")
    assert is_valid_event(event, _make_helper(), _make_config()) is False


def test_is_valid_event_rejects_unknown_event_type():
    event = _base_event(event_type="merge")
    assert is_valid_event(event, _make_helper(), _make_config()) is False


def test_is_valid_event_rejects_disallowed_observable_type():
    event = _base_event(extensions={"ext-1": {"main_observable_type": "Domain-Name"}})
    assert is_valid_event(event, _make_helper(), _make_config(["ip_address"])) is False


def test_is_valid_event_rejects_type_not_in_multi_type_config():
    event = _base_event(extensions={"ext-1": {"main_observable_type": "StixFile"}})
    assert (
        is_valid_event(event, _make_helper(), _make_config(["ip_address", "domain"]))
        is False
    )


def test_is_valid_event_rejects_expired_indicator():
    event = _base_event(valid_until=_past_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is False


def test_is_valid_event_accepts_no_valid_until():
    event = _base_event()
    del event["valid_until"]
    assert is_valid_event(event, _make_helper(), _make_config()) is True


def test_is_valid_event_rejects_missing_observable_type():
    event = _base_event(extensions={"ext-1": {}})
    assert is_valid_event(event, _make_helper(), _make_config()) is False


# ---------------------------------------------------------------------------
# is_valid_event: ``Z``-suffixed ``valid_until`` handling
# ---------------------------------------------------------------------------
#
# OpenCTI / STIX stream payloads commonly serialise ``valid_until``
# as RFC3339 with a trailing ``Z`` (e.g. ``2024-04-29T12:33:20.098Z``).
# ``datetime.fromisoformat`` only learned to accept that suffix in
# Python 3.11, so on older runtimes the previous shape raised
# ``ValueError`` and crashed the stream callback for the offending
# event. The fix normalises the ``Z`` to ``+00:00`` first.


def _future_z_timestamp():
    return (
        (datetime.now(timezone.utc) + timedelta(days=1))
        .replace(microsecond=98000)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _past_z_timestamp():
    return (
        (datetime.now(timezone.utc) - timedelta(days=1))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def test_is_valid_event_accepts_z_suffixed_future_valid_until():
    event = _base_event(valid_until=_future_z_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is True


def test_is_valid_event_rejects_z_suffixed_expired_valid_until():
    event = _base_event(valid_until=_past_z_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is False


def test_is_valid_event_does_not_crash_on_unparseable_valid_until():
    # ``_parse_valid_until`` returns ``None`` on unparseable input;
    # ``is_valid_event`` must treat that as "no expiry information"
    # and accept the event rather than raising. Prevents a malformed
    # upstream payload from killing the stream callback for every
    # subsequent event.
    event = _base_event(valid_until="not-a-date")
    assert is_valid_event(event, _make_helper(), _make_config()) is True


# ---------------------------------------------------------------------------
# is_valid_event: ``delete`` events bypass the ``valid_until`` filter
# ---------------------------------------------------------------------------
#
# The previous shape silently dropped delete events for expired
# indicators — even though the delete still needs to reach Datadog so
# a previously-forwarded record is removed from the remote feed.
# Otherwise Datadog stays out of sync with OpenCTI as soon as an
# indicator expires AND is then deleted on the OpenCTI side.


def test_is_valid_event_delete_passes_through_expired_valid_until():
    event = _base_event(event_type="delete", valid_until=_past_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is True


def test_is_valid_event_delete_passes_through_expired_z_suffixed_valid_until():
    event = _base_event(event_type="delete", valid_until=_past_z_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is True


def test_is_valid_event_create_still_rejected_when_expired():
    # Sanity-check that the delete-bypass does NOT widen the gate for
    # create / update events on an expired indicator.
    event = _base_event(event_type="create", valid_until=_past_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is False
    event = _base_event(event_type="update", valid_until=_past_timestamp())
    assert is_valid_event(event, _make_helper(), _make_config()) is False


# ---------------------------------------------------------------------------
# indicator_type_for_event
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "observable_type, expected",
    [
        pytest.param("IPv4-Addr", "ip_address", id="IPv4"),
        pytest.param("IPv6-Addr", "ip_address", id="IPv6"),
        pytest.param("Domain-Name", "domain", id="domain"),
        pytest.param("StixFile", "sha256", id="sha256"),
        pytest.param("Unknown-Type", None, id="unknown"),
    ],
)
def test_indicator_type_for_event(observable_type, expected):
    event = {"extensions": {"ext-1": {"main_observable_type": observable_type}}}
    assert indicator_type_for_event(event) == expected


def test_indicator_type_for_event_no_observable_type():
    assert indicator_type_for_event({}) is None


# ---------------------------------------------------------------------------
# STIX_TYPE_TO_INDICATOR_TYPE coverage
# ---------------------------------------------------------------------------


def test_stix_type_to_indicator_type_contents():
    assert STIX_TYPE_TO_INDICATOR_TYPE == {
        "IPv4-Addr": "ip_address",
        "IPv6-Addr": "ip_address",
        "Domain-Name": "domain",
        "StixFile": "sha256",
    }
