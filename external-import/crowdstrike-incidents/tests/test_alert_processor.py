"""Tests for the CrowdStrike alert processor (collection, mapping, checkpoint)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connectors_sdk.models import TLPMarking
from connectors_sdk.models.enums import IncidentSeverity, IncidentType
from crowdstrike_incidents.models import CrowdstrikeAlert
from crowdstrike_incidents.processors.alert_processor import (
    AUTHOR,
    AlertProcessor,
    CrowdstrikeIncidentsState,
)
from crowdstrike_incidents.settings import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_processor(
    severity_min: Severity | None = None,
    last_updated_timestamp: str | None = None,
) -> AlertProcessor:
    proc = AlertProcessor.__new__(AlertProcessor)
    proc._config = SimpleNamespace(
        products=["ngsiem"],
        severity_min=severity_min,
        include_hidden=False,
        import_start_date=timedelta(days=7),
    )
    proc._marking = TLPMarking(level="amber+strict")
    proc._client = MagicMock()
    proc.logger = MagicMock()
    proc.work_manager = MagicMock()
    proc.state = CrowdstrikeIncidentsState(
        last_updated_timestamp=last_updated_timestamp
    )
    proc.work_name = "test"
    return proc


def _of_type(objects: list, stix_type: str) -> list:
    return [
        obj
        for obj in objects
        if hasattr(obj, "id") and obj.id.startswith(f"{stix_type}--")
    ]


def _convert(data: dict, **kwargs) -> list:
    return _make_processor(**kwargs)._convert_alert(
        CrowdstrikeAlert.model_validate(data)
    )


def _incident(objects: list):
    (incident,) = _of_type(objects, "incident")
    return incident


def _relationships(objects: list, relationship_type: str) -> list:
    return [
        obj
        for obj in _of_type(objects, "relationship")
        if obj.type == relationship_type
    ]


T1059 = {
    "pattern_id": 1,
    "tactic_id": "TA0002",
    "tactic": "Execution",
    "technique_id": "T1059",
    "technique": "Command and Scripting Interpreter",
}

# ---------------------------------------------------------------------------
# Incident mapping
# ---------------------------------------------------------------------------


def test_incident_core_fields(ngsiem_alert_data):
    incident = _incident(_convert(ngsiem_alert_data))

    assert incident.incident_type == IncidentType.ALERT
    assert incident.source == "CrowdStrike Falcon Next-Gen SIEM"
    assert incident.author == AUTHOR
    assert incident.markings == [TLPMarking(level="amber+strict")]


def test_incident_name_identifies_rule_host_and_user(ngsiem_alert_data):
    incident = _incident(_convert(ngsiem_alert_data))

    assert incident.name == "Synthetic Rule A on host-a.example.org by synthetic-user"


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"user_names": [], "users": []}, "Synthetic Rule A on host-a.example.org"),
        ({"host_names": []}, "Synthetic Rule A by synthetic-user"),
        (
            {"display_name": None},
            "Synthetic Rule A on host-a.example.org by synthetic-user",
        ),
        (
            {
                "display_name": None,
                "name": None,
                "host_names": [],
                "user_names": [],
                "users": [],
            },
            "33333333333333333333333333333333:ngsiem:33333333333333333333333333333333:44444444444444444444444444444444",
        ),
    ],
)
def test_incident_name_fallbacks(ngsiem_alert_data, overrides, expected):
    ngsiem_alert_data.update(overrides)

    assert _incident(_convert(ngsiem_alert_data)).name == expected


def test_incident_user_name_falls_back_to_users(ngsiem_alert_data):
    ngsiem_alert_data["user_names"] = []

    assert _incident(_convert(ngsiem_alert_data)).name.endswith("by synthetic-user")


def test_incident_links_back_to_the_console(ngsiem_alert_data):
    (reference,) = _incident(_convert(ngsiem_alert_data)).external_references

    assert reference.source_name == "CrowdStrike Falcon Next-Gen SIEM"
    assert reference.url == ngsiem_alert_data["falcon_host_link"]
    assert reference.external_id == ngsiem_alert_data["composite_id"]


def test_incident_timeline(ngsiem_alert_data):
    incident = _incident(_convert(ngsiem_alert_data))

    assert incident.created == datetime(
        2025, 1, 15, 10, 4, 30, 987654, tzinfo=timezone.utc
    )
    assert incident.first_seen == datetime(2025, 1, 15, 9, 59, tzinfo=timezone.utc)
    assert incident.last_seen == datetime(2025, 1, 15, 10, 0, tzinfo=timezone.utc)


def test_incident_description_keeps_rule_and_detection_context(ngsiem_alert_data):
    description = _incident(_convert(ngsiem_alert_data)).description

    assert description.startswith("Synthetic correlation rule description")
    assert "| Product | ngsiem |" in description
    assert "| Status | new |" in description
    assert "| Priority | 1 |" in description
    assert "Synthetic priority explanation" in description
    assert ngsiem_alert_data["detection_id"] in description
    assert ngsiem_alert_data["event_ids"] in description


@pytest.mark.parametrize(
    "crowdstrike_severity, opencti_severity",
    [
        ("Informational", IncidentSeverity.LOW),
        ("Low", IncidentSeverity.LOW),
        ("Medium", IncidentSeverity.MEDIUM),
        ("High", IncidentSeverity.HIGH),
        ("Critical", IncidentSeverity.CRITICAL),
        ("Unknown", None),
        (None, None),
    ],
)
def test_severity_mapping(ngsiem_alert_data, crowdstrike_severity, opencti_severity):
    ngsiem_alert_data["severity_name"] = crowdstrike_severity

    assert _incident(_convert(ngsiem_alert_data)).severity == opencti_severity


def test_incident_id_is_deterministic_across_updates(ngsiem_alert_data):
    first = _incident(_convert(ngsiem_alert_data))
    ngsiem_alert_data["status"] = "in_progress"
    ngsiem_alert_data["updated_timestamp"] = "2025-01-16T00:00:00Z"
    second = _incident(_convert(ngsiem_alert_data))

    assert first.id == second.id
    assert first.id.startswith("incident--")


# ---------------------------------------------------------------------------
# Observables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, value, stix_type",
    [
        ("host_names", ["host-a.example.org"], "hostname"),
        ("source_ips", ["192.0.2.10"], "ipv4-addr"),
        ("source_ips", ["2001:db8::1"], "ipv6-addr"),
    ],
)
def test_observables_are_related_to_the_incident(
    ngsiem_alert_data, field, value, stix_type
):
    ngsiem_alert_data[field] = value
    objects = _convert(ngsiem_alert_data)

    (observable,) = _of_type(objects, stix_type)
    assert observable.value == value[0]
    assert observable.author == AUTHOR
    assert any(
        rel.source.id == _incident(objects).id and rel.target.id == observable.id
        for rel in _relationships(objects, "related-to")
    )


def test_user_account_from_users(ngsiem_alert_data):
    objects = _convert(ngsiem_alert_data)

    (account,) = _of_type(objects, "user-account")
    assert account.account_login == "synthetic-user"
    assert account.user_id == "S-1-5-21-0000000000-0000000000-0000000000-1001"
    assert any(
        rel.target.id == account.id for rel in _relationships(objects, "related-to")
    )


def test_user_account_from_user_names_only(ngsiem_alert_data):
    ngsiem_alert_data["users"] = []
    ngsiem_alert_data["user_names"] = ["other-user"]

    (account,) = _of_type(_convert(ngsiem_alert_data), "user-account")
    assert account.account_login == "other-user"


def test_invalid_ip_is_skipped(ngsiem_alert_data):
    ngsiem_alert_data["source_ips"] = ["not-an-ip", "192.0.2.10"]

    objects = _convert(ngsiem_alert_data)

    assert [ip.value for ip in _of_type(objects, "ipv4-addr")] == ["192.0.2.10"]


def test_duplicate_values_create_a_single_observable(ngsiem_alert_data):
    ngsiem_alert_data["host_names"] = ["host-a.example.org", "host-a.example.org"]

    assert len(_of_type(_convert(ngsiem_alert_data), "hostname")) == 1


def test_alert_without_assets(ngsiem_alert_data):
    ngsiem_alert_data.update(
        {"host_names": [], "source_ips": [], "users": [], "user_names": []}
    )

    objects = _convert(ngsiem_alert_data)

    assert len(_of_type(objects, "incident")) == 1
    assert _of_type(objects, "relationship") == []


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------


def test_mitre_technique_is_linked_with_uses(ngsiem_alert_data):
    ngsiem_alert_data["mitre_attack"] = [T1059]
    objects = _convert(ngsiem_alert_data)

    (pattern,) = _of_type(objects, "attack-pattern")
    assert pattern.mitre_id == "T1059"
    assert pattern.name == "Command and Scripting Interpreter"
    (uses,) = _relationships(objects, "uses")
    assert uses.source.id == _incident(objects).id
    assert uses.target.id == pattern.id


def test_mitre_technique_id_matches_the_attack_dataset(ngsiem_alert_data):
    """The STIX id only depends on the MITRE id, so it merges with existing TTPs."""
    ngsiem_alert_data["mitre_attack"] = [T1059]
    first = _of_type(_convert(ngsiem_alert_data), "attack-pattern")[0]
    ngsiem_alert_data["mitre_attack"] = [{**T1059, "technique": "Another name"}]
    second = _of_type(_convert(ngsiem_alert_data), "attack-pattern")[0]

    assert first.id == second.id


def test_mitre_tactics_become_labels(ngsiem_alert_data):
    ngsiem_alert_data["mitre_attack"] = [
        T1059,
        {**T1059, "technique_id": "T1059.001", "technique": "PowerShell"},
        {
            "tactic": "Persistence",
            "technique_id": "T1053",
            "technique": "Scheduled Task/Job",
        },
    ]

    assert _incident(_convert(ngsiem_alert_data)).labels == ["Execution", "Persistence"]


def test_non_mitre_technique_ids_are_ignored(ngsiem_alert_data):
    ngsiem_alert_data["mitre_attack"] = [
        {"tactic": "Custom", "technique_id": "CST0001", "technique": "Proprietary"}
    ]

    objects = _convert(ngsiem_alert_data)

    assert _of_type(objects, "attack-pattern") == []
    assert _incident(objects).labels == ["Custom"]


def test_alert_without_mitre(ngsiem_alert_data):
    objects = _convert(ngsiem_alert_data)

    assert _of_type(objects, "attack-pattern") == []
    assert _relationships(objects, "uses") == []
    assert _incident(objects).labels is None


# ---------------------------------------------------------------------------
# Bundle invariants
# ---------------------------------------------------------------------------


def test_every_object_has_author_and_marking(ngsiem_alert_data):
    ngsiem_alert_data["mitre_attack"] = [T1059]
    objects = _convert(ngsiem_alert_data)

    assert AUTHOR in objects
    for obj in objects:
        if obj is AUTHOR or isinstance(obj, TLPMarking):
            continue
        assert obj.author == AUTHOR
        assert obj.markings == [TLPMarking(level="amber+strict")]


def test_bundle_serialises_to_stix(ngsiem_alert_data):
    ngsiem_alert_data["mitre_attack"] = [T1059]

    for obj in _convert(ngsiem_alert_data):
        assert obj.to_stix2_object() is not None


# ---------------------------------------------------------------------------
# transform(): filters, failures, dedup, cursor
# ---------------------------------------------------------------------------


def _alert(data: dict, index: int, **overrides) -> dict:
    return {
        **data,
        "composite_id": f"alert-{index}",
        "created_timestamp": f"2025-01-15T10:00:0{index}Z",
        "updated_timestamp": f"2025-01-15T11:00:0{index}Z",
        **overrides,
    }


def test_transform_yields_one_bundle_per_page_with_its_cursor(ngsiem_alert_data):
    proc = _make_processor()
    pages = [
        [_alert(ngsiem_alert_data, 1), _alert(ngsiem_alert_data, 2)],
        [_alert(ngsiem_alert_data, 3)],
    ]

    bundles = list(proc.transform(iter(pages)))

    assert [cursor for _, cursor in bundles] == [
        "2025-01-15T11:00:02Z",
        "2025-01-15T11:00:03Z",
    ]
    assert len(_of_type(bundles[0][0], "incident")) == 2


def test_transform_deduplicates_shared_objects(ngsiem_alert_data):
    proc = _make_processor()
    page = [_alert(ngsiem_alert_data, 1), _alert(ngsiem_alert_data, 2)]

    ((objects, _),) = list(proc.transform(iter([page])))

    ids = [obj.id for obj in objects if hasattr(obj, "id")]
    assert len(ids) == len(set(ids))
    assert len(_of_type(objects, "hostname")) == 1


def test_transform_skips_alerts_below_minimum_severity(ngsiem_alert_data):
    proc = _make_processor(severity_min=Severity.HIGH)
    page = [
        _alert(ngsiem_alert_data, 1, severity_name="Medium"),
        _alert(ngsiem_alert_data, 2, severity_name="High"),
        _alert(ngsiem_alert_data, 3, severity_name=None),
    ]

    ((objects, cursor),) = list(proc.transform(iter([page])))

    names = {
        i.external_references[0].external_id for i in _of_type(objects, "incident")
    }
    # Alerts without a known severity are always imported
    assert names == {"alert-2", "alert-3"}
    # The cursor still moves past the filtered alert
    assert cursor == "2025-01-15T11:00:03Z"


def test_transform_skips_unsupported_products(ngsiem_alert_data):
    proc = _make_processor()
    page = [_alert(ngsiem_alert_data, 1, product="epp"), _alert(ngsiem_alert_data, 2)]

    ((objects, _),) = list(proc.transform(iter([page])))

    assert len(_of_type(objects, "incident")) == 1


def test_transform_logs_and_skips_invalid_alerts(ngsiem_alert_data):
    proc = _make_processor()
    page = [{"composite_id": "broken"}, _alert(ngsiem_alert_data, 2)]

    ((objects, cursor),) = list(proc.transform(iter([page])))

    assert len(_of_type(objects, "incident")) == 1
    assert cursor == "2025-01-15T11:00:02Z"
    proc.logger.error.assert_called_once()


def test_transform_yields_cursor_even_when_every_alert_is_filtered(ngsiem_alert_data):
    proc = _make_processor(severity_min=Severity.CRITICAL)
    page = [_alert(ngsiem_alert_data, 1, severity_name="Low")]

    assert list(proc.transform(iter([page]))) == [([], "2025-01-15T11:00:01Z")]


# ---------------------------------------------------------------------------
# collect() and checkpointing
# ---------------------------------------------------------------------------


def test_first_run_starts_from_import_start_date():
    proc = _make_processor()
    proc._client.iter_alert_pages.return_value = iter([])

    list(proc.collect())

    since = proc._client.iter_alert_pages.call_args.kwargs["since"]
    expected = datetime.now(timezone.utc) - timedelta(days=7)
    parsed = datetime.strptime(since, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert abs(parsed - expected) < timedelta(seconds=5)
    assert proc._client.iter_alert_pages.call_args.kwargs["products"] == ["ngsiem"]
    assert proc._client.iter_alert_pages.call_args.kwargs["include_hidden"] is False


def test_next_runs_resume_from_the_stored_cursor():
    proc = _make_processor(last_updated_timestamp="2025-01-15T11:00:02.123456789Z")
    proc._client.iter_alert_pages.return_value = iter([])

    list(proc.collect())

    assert (
        proc._client.iter_alert_pages.call_args.kwargs["since"]
        == "2025-01-15T11:00:02.123456789Z"
    )


def test_collect_streams_pages():
    proc = _make_processor()
    proc._client.iter_alert_pages.return_value = iter([["a"], ["b"]])

    assert list(proc.collect()) == [["a"], ["b"]]


@pytest.fixture
def state_save(mocker) -> MagicMock:
    """Patch the state persistence, which needs an OpenCTI helper."""
    return mocker.patch.object(CrowdstrikeIncidentsState, "save", autospec=True)


def test_send_checkpoints_the_cursor_after_each_bundle(state_save):
    proc = _make_processor()
    saved: list[str | None] = []
    state_save.side_effect = lambda state: saved.append(state.last_updated_timestamp)

    proc.send(
        iter([(["obj-1"], "cursor-1"), ([], "cursor-2"), (["obj-3"], "cursor-3")])
    )

    assert proc.work_manager.send.call_count == 2
    assert saved == ["cursor-1", "cursor-2", "cursor-3"]


def test_cursor_is_not_saved_when_sending_fails(state_save):
    proc = _make_processor()
    proc.work_manager.send.side_effect = RuntimeError("queue down")

    with pytest.raises(RuntimeError):
        proc.send(iter([(["obj-1"], "cursor-1")]))

    state_save.assert_not_called()
    assert proc.state.last_updated_timestamp is None
