"""Tests for the enrichment of Incidents with the alert source event (threat side)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from conftest import load_resource
from crowdstrike_incidents.models import CrowdstrikeAlert, SourceEvent
from crowdstrike_incidents.processors.alert_processor import AUTHOR
from crowdstrike_incidents.settings import Severity
from test_alert_processor import (
    _alert,
    _convert,
    _incident,
    _make_processor,
    _of_type,
    _page,
    _relationships,
)


@pytest.fixture
def source_event_data() -> dict:
    return load_resource("ngsiem_source_event.json")


def _convert_with_event(alert_data: dict, event_data: dict) -> list:
    return _make_processor()._convert_alert(
        CrowdstrikeAlert.model_validate(alert_data),
        SourceEvent.model_validate(event_data),
    )


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


def test_source_event_model(source_event_data):
    event = SourceEvent.model_validate(source_event_data)

    assert event.indicator_id == "44444444444444444444444444444444"
    assert event.file_name == "synthetic-implant.exe"
    assert event.sha1 == "0" * 40
    assert event.parent_name == "powershell.exe"
    assert event.grandparent_name == "cmd.exe"
    assert event.agent_public_ip == "203.0.113.10"


def test_source_event_blank_values_are_dropped(source_event_data):
    source_event_data["Vendor.FileName"] = "  "
    source_event_data["process.command_line"] = ""

    event = SourceEvent.model_validate(source_event_data)

    assert event.file_name is None
    assert event.command_line is None


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def test_executed_file_is_related_to_the_incident(ngsiem_alert_data, source_event_data):
    objects = _convert_with_event(ngsiem_alert_data, source_event_data)

    (file,) = _of_type(objects, "file")
    assert file.name == "synthetic-implant.exe"
    assert file.hashes["SHA-256"] == "2" * 64
    assert file.hashes["MD5"] == "1" * 32
    assert file.author == AUTHOR
    assert any(
        rel.target.id == file.id for rel in _relationships(objects, "related-to")
    )
    # No IoC yet: Indicator creation is a later, optional feature
    assert _of_type(objects, "indicator") == []


def test_placeholder_hashes_are_dropped(ngsiem_alert_data, source_event_data):
    """An all-zero hash is a CrowdStrike placeholder: OpenCTI matches Files on
    any of their hashes, so sending it would merge unrelated binaries."""
    (file,) = _of_type(
        _convert_with_event(ngsiem_alert_data, source_event_data), "file"
    )

    assert "SHA-1" not in file.hashes
    assert file.hashes["SHA-256"] == "2" * 64
    assert file.hashes["MD5"] == "1" * 32


def test_binaries_sharing_a_placeholder_hash_stay_distinct(
    ngsiem_alert_data, source_event_data
):
    other_binary = {
        **source_event_data,
        "process.hash.sha256": "3" * 64,
        "process.hash.md5": "4" * 32,
    }

    (first,) = _of_type(
        _convert_with_event(ngsiem_alert_data, source_event_data), "file"
    )
    (second,) = _of_type(_convert_with_event(ngsiem_alert_data, other_binary), "file")

    assert first.id != second.id
    assert not set(first.hashes.values()) & set(second.hashes.values())


def test_file_with_only_placeholder_hashes_keeps_its_name(
    ngsiem_alert_data, source_event_data
):
    source_event_data.update(
        {"process.hash.sha256": "0" * 64, "process.hash.md5": "0" * 32}
    )

    (file,) = _of_type(
        _convert_with_event(ngsiem_alert_data, source_event_data), "file"
    )

    assert file.name == "synthetic-implant.exe"
    assert file.hashes is None


def test_file_with_name_only(ngsiem_alert_data, source_event_data):
    for key in ("process.hash.sha256", "process.hash.md5", "process.hash.sha1"):
        source_event_data.pop(key)

    (file,) = _of_type(
        _convert_with_event(ngsiem_alert_data, source_event_data), "file"
    )

    assert file.name == "synthetic-implant.exe"
    assert file.hashes is None


def test_no_file_without_name_nor_hash(ngsiem_alert_data, source_event_data):
    for key in (
        "Vendor.FileName",
        "process.hash.sha256",
        "process.hash.md5",
        "process.hash.sha1",
    ):
        source_event_data.pop(key)

    objects = _convert_with_event(ngsiem_alert_data, source_event_data)

    assert _of_type(objects, "file") == []


def test_agent_public_ip_is_related_to_the_incident(
    ngsiem_alert_data, source_event_data
):
    objects = _convert_with_event(ngsiem_alert_data, source_event_data)

    ips = sorted(ip.value for ip in _of_type(objects, "ipv4-addr"))
    assert ips == ["192.0.2.10", "203.0.113.10"]


def test_agent_public_ip_already_in_the_alert_is_not_duplicated(
    ngsiem_alert_data, source_event_data
):
    source_event_data["Vendor.aip"] = "192.0.2.10"

    objects = _convert_with_event(ngsiem_alert_data, source_event_data)

    assert [ip.value for ip in _of_type(objects, "ipv4-addr")] == ["192.0.2.10"]


def test_execution_context_is_in_a_note_on_the_incident(
    ngsiem_alert_data, source_event_data
):
    event = SourceEvent.model_validate(source_event_data)
    objects = _convert_with_event(ngsiem_alert_data, source_event_data)
    incident = _incident(objects)

    (note,) = _of_type(objects, "note")
    assert [obj.id for obj in note.objects] == [incident.id]
    assert note.author == AUTHOR
    assert f"| Command line | {event.command_line} |" in note.content
    assert f"| Executable | {event.executable} |" in note.content
    assert (
        "| Process chain | cmd.exe → powershell.exe → synthetic-implant.exe |"
        in note.content
    )
    assert "Command line" not in incident.description


def test_execution_note_is_stable(ngsiem_alert_data, source_event_data):
    first = _of_type(_convert_with_event(ngsiem_alert_data, source_event_data), "note")
    second = _of_type(_convert_with_event(ngsiem_alert_data, source_event_data), "note")

    assert first[0].id == second[0].id


def test_update_without_enrichment_keeps_the_execution_context(
    ngsiem_alert_data, source_event_data
):
    """Regression (review): an update imported while the enrichment is
    unavailable must not erase the execution context. It lives in a Note that
    is only sent with the source event, and the description never holds it."""
    enriched = _convert_with_event(ngsiem_alert_data, source_event_data)
    updated = _convert({**ngsiem_alert_data, "status": "in_progress"})

    assert _of_type(updated, "note") == []
    assert _incident(updated).description == _incident(enriched).description.replace(
        "| Status | new |", "| Status | in_progress |"
    )


def test_event_mitre_names_are_ignored(ngsiem_alert_data, source_event_data):
    objects = _convert_with_event(ngsiem_alert_data, source_event_data)

    assert _of_type(objects, "attack-pattern") == []
    assert _incident(objects).labels is None


def test_enrichment_does_not_change_the_incident_id(
    ngsiem_alert_data, source_event_data
):
    without_event = _incident(_convert(ngsiem_alert_data))
    with_event = _incident(_convert_with_event(ngsiem_alert_data, source_event_data))

    assert without_event.id == with_event.id


# ---------------------------------------------------------------------------
# transform(): search per page, matching, failures
# ---------------------------------------------------------------------------


def test_enrichment_disabled_sends_no_search(ngsiem_alert_data):
    proc = _make_processor(events_client=None)

    ((objects, _),) = list(proc.transform(iter([_page([ngsiem_alert_data])])))

    assert len(_of_type(objects, "incident")) == 1
    assert _of_type(objects, "file") == []


def test_one_search_per_page_and_events_matched_by_indicator_id(
    ngsiem_alert_data, source_event_data
):
    events_client = MagicMock()
    events_client.get_source_events.return_value = [source_event_data]
    proc = _make_processor(events_client=events_client)
    page = _page(
        [
            ngsiem_alert_data,
            _alert(ngsiem_alert_data, 2, composite_id="cid:ngsiem:cid:no-event"),
        ]
    )

    ((objects, _),) = list(proc.transform(iter([page])))

    events_client.get_source_events.assert_called_once()
    ids = events_client.get_source_events.call_args.args[0]
    assert ids == ["44444444444444444444444444444444", "no-event"]
    # Only the alert whose source event exists gets the threat observables
    assert len(_of_type(objects, "incident")) == 2
    assert len(_of_type(objects, "file")) == 1


def test_search_window_covers_the_oldest_detection_window(ngsiem_alert_data):
    events_client = MagicMock()
    events_client.get_source_events.return_value = []
    proc = _make_processor(events_client=events_client)
    older = _alert(ngsiem_alert_data, 2, start_time="2025-01-08T09:00:00Z")

    list(proc.transform(iter([_page([ngsiem_alert_data, older])])))

    since = events_client.get_source_events.call_args.kwargs["since"]
    assert since == datetime(2025, 1, 8, 8, 0, tzinfo=timezone.utc)


def test_search_failure_keeps_the_incidents(ngsiem_alert_data):
    events_client = MagicMock()
    events_client.get_source_events.side_effect = RuntimeError("403 scope")
    proc = _make_processor(events_client=events_client)

    ((objects, _),) = list(proc.transform(iter([_page([ngsiem_alert_data])])))

    assert len(_of_type(objects, "incident")) == 1
    assert len(_of_type(objects, "hostname")) == 1
    assert _of_type(objects, "file") == []
    proc.logger.warning.assert_called_once()


def test_invalid_source_event_is_skipped(ngsiem_alert_data):
    events_client = MagicMock()
    events_client.get_source_events.return_value = [{"no": "indicator id"}]
    proc = _make_processor(events_client=events_client)

    ((objects, _),) = list(proc.transform(iter([_page([ngsiem_alert_data])])))

    assert len(_of_type(objects, "incident")) == 1
    assert _of_type(objects, "file") == []


def test_no_search_when_every_alert_is_filtered(ngsiem_alert_data):
    events_client = MagicMock()
    proc = _make_processor(severity_min=Severity.CRITICAL, events_client=events_client)
    page = _page([_alert(ngsiem_alert_data, 1, severity_name="Low")])

    list(proc.transform(iter([page])))

    events_client.get_source_events.assert_not_called()


@pytest.mark.parametrize(
    "key, value",
    [
        ("process.hash.sha256", "abc"),
        ("process.hash.md5", "N/A"),
        ("process.hash.sha1", "z" * 40),
    ],
)
def test_malformed_hash_is_dropped_and_the_incident_kept(
    ngsiem_alert_data, source_event_data, key, value
):
    source_event_data[key] = value

    objects = _convert_with_event(ngsiem_alert_data, source_event_data)

    assert len(_of_type(objects, "incident")) == 1
    (file,) = _of_type(objects, "file")
    assert value not in (file.hashes or {}).values()


def test_uppercase_hashes_are_accepted(ngsiem_alert_data, source_event_data):
    source_event_data["process.hash.sha256"] = "A" * 64

    (file,) = _of_type(
        _convert_with_event(ngsiem_alert_data, source_event_data), "file"
    )

    assert file.hashes["SHA-256"] == "A" * 64
