"""Tests for the CrowdStrike alert payload models."""

from datetime import datetime, timezone

import pytest
from crowdstrike_incidents.models import CrowdstrikeAlert
from pydantic import ValidationError


def test_parse_full_alert(ngsiem_alert_data):
    alert = CrowdstrikeAlert.model_validate(ngsiem_alert_data)

    assert alert.composite_id == ngsiem_alert_data["composite_id"]
    assert alert.display_name == "Synthetic Rule A"
    assert alert.product == "ngsiem"
    assert alert.severity_name == "High"
    assert alert.host_names == ["host-a.example.org"]
    assert alert.source_ips == ["192.0.2.10"]
    assert alert.users[0].user_name == "synthetic-user"
    assert alert.users[0].sid == "S-1-5-21-0000000000-0000000000-0000000000-1001"
    assert alert.mitre_attack == []


def test_timestamps_with_nanoseconds_are_parsed_as_utc(ngsiem_alert_data):
    alert = CrowdstrikeAlert.model_validate(ngsiem_alert_data)

    assert alert.created_timestamp == datetime(
        2025, 1, 15, 10, 4, 30, 987654, tzinfo=timezone.utc
    )
    assert alert.start_time == datetime(2025, 1, 15, 9, 59, tzinfo=timezone.utc)
    assert alert.end_time == datetime(2025, 1, 15, 10, 0, tzinfo=timezone.utc)


def test_raw_updated_timestamp_is_kept_verbatim(ngsiem_alert_data):
    alert = CrowdstrikeAlert.model_validate(ngsiem_alert_data)

    assert alert.updated_timestamp == "2025-01-15T10:04:30.987654321Z"


@pytest.mark.parametrize(
    "field",
    ["host_names", "source_ips", "users", "user_names", "mitre_attack"],
)
@pytest.mark.parametrize("empty_value", [None, []])
def test_null_lists_are_coalesced(ngsiem_alert_data, field, empty_value):
    ngsiem_alert_data[field] = empty_value

    alert = CrowdstrikeAlert.model_validate(ngsiem_alert_data)

    assert getattr(alert, field) == []


def test_missing_optional_fields(ngsiem_alert_data):
    for field in [
        "display_name",
        "description",
        "start_time",
        "end_time",
        "falcon_host_link",
        "severity_name",
        "host_names",
        "users",
        "event_ids",
    ]:
        ngsiem_alert_data.pop(field)

    alert = CrowdstrikeAlert.model_validate(ngsiem_alert_data)

    assert alert.display_name is None
    assert alert.start_time is None
    assert alert.host_names == []
    assert alert.event_ids == []


@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            "00000000-0000-4000-8000-000000000002",
            ["00000000-0000-4000-8000-000000000002"],
        ),
        (["id-1", "id-2"], ["id-1", "id-2"]),
        (None, []),
        ("", []),
    ],
)
def test_event_ids_accept_string_or_list(ngsiem_alert_data, raw, expected):
    ngsiem_alert_data["event_ids"] = raw

    assert CrowdstrikeAlert.model_validate(ngsiem_alert_data).event_ids == expected


def test_mitre_attack_entries(ngsiem_alert_data):
    ngsiem_alert_data["mitre_attack"] = [
        {
            "pattern_id": 1,
            "tactic_id": "TA0002",
            "tactic": "Execution",
            "technique_id": "T1059",
            "technique": "Command and Scripting Interpreter",
        }
    ]

    technique = CrowdstrikeAlert.model_validate(ngsiem_alert_data).mitre_attack[0]

    assert technique.technique_id == "T1059"
    assert technique.tactic == "Execution"


@pytest.mark.parametrize(
    "field", ["composite_id", "created_timestamp", "updated_timestamp"]
)
def test_required_fields(ngsiem_alert_data, field):
    ngsiem_alert_data.pop(field)

    with pytest.raises(ValidationError):
        CrowdstrikeAlert.model_validate(ngsiem_alert_data)


def test_lenient_values(ngsiem_alert_data):
    ngsiem_alert_data.update(
        {
            "priority_value": 1.5,
            "host_names": [None, " host-b.example.org ", ""],
            "users": [None, {"user_name": " synthetic-user ", "sid": " "}],
            "mitre_attack": [None, {"technique_id": " T1059 ", "tactic": " "}],
        }
    )

    alert = CrowdstrikeAlert.model_validate(ngsiem_alert_data)

    assert alert.priority_value == 1.5
    assert alert.host_names == ["host-b.example.org"]
    assert alert.users[0].user_name == "synthetic-user"
    assert alert.users[0].sid is None
    assert alert.mitre_attack[0].technique_id == "T1059"
    assert alert.mitre_attack[0].tactic is None
