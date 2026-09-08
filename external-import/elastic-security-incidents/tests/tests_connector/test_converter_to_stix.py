import uuid
from unittest.mock import MagicMock

import stix2
from connector.converter_to_stix import ConverterToStix

INCIDENT_ID = f"incident--{uuid.uuid4()}"


def _make_converter() -> ConverterToStix:
    helper = MagicMock()
    helper.connect_name = "Elastic Security Incidents"
    return ConverterToStix(helper, MagicMock(), stix2.TLP_AMBER)


def _make_alert(**overrides):
    alert = {
        "kibana.alert.rule.note": "Check the source IP against the allowlist.",
        "kibana.alert.rule.name": "Suspicious login",
        "kibana.alert.uuid": "alert-1",
        "@timestamp": "2026-01-01T00:00:00.000Z",
    }
    alert.update(overrides)
    return alert


def test_investigation_note_id_is_stable_across_alerts_from_same_rule():
    # Two different alerts fired by the same rule carry the same investigation
    # guide text; they should collapse into the same STIX Note rather than
    # each alert minting its own duplicate.
    converter = _make_converter()

    first = converter.create_investigation_note(
        _make_alert(
            **{"kibana.alert.uuid": "alert-1", "@timestamp": "2026-01-01T00:00:00.000Z"}
        ),
        incident_id=INCIDENT_ID,
    )
    second = converter.create_investigation_note(
        _make_alert(
            **{"kibana.alert.uuid": "alert-2", "@timestamp": "2026-01-02T00:00:00.000Z"}
        ),
        incident_id=INCIDENT_ID,
    )

    assert first.id == second.id


def test_investigation_note_id_differs_for_different_guide_text():
    converter = _make_converter()

    first = converter.create_investigation_note(
        _make_alert(**{"kibana.alert.rule.note": "Guide A"}), incident_id=INCIDENT_ID
    )
    second = converter.create_investigation_note(
        _make_alert(**{"kibana.alert.rule.note": "Guide B"}), incident_id=INCIDENT_ID
    )

    assert first.id != second.id


def test_investigation_note_returns_none_without_a_guide():
    converter = _make_converter()

    note = converter.create_investigation_note(
        _make_alert(**{"kibana.alert.rule.note": ""}), incident_id=INCIDENT_ID
    )

    assert note is None
