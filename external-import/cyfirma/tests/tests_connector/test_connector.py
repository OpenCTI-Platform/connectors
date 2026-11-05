"""Unit tests for connector.connector.CyfirmaConnector."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from connector.connector import CyfirmaConnector
from pydantic import SecretStr

TLP_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"


@pytest.fixture
def config():
    cfg = MagicMock()
    cfg.cyfirma.api_base_url = "https://api.cyfirma.test"
    cfg.cyfirma.api_key = SecretStr("secret")
    cfg.cyfirma.tailored_iocs = True
    cfg.cyfirma.tailored_vulnerabilities = False
    cfg.cyfirma.look_back_days = 5
    cfg.cyfirma.tlp_level = "clear"
    cfg.connector.duration_period = timedelta(hours=1)
    return cfg


@pytest.fixture
def helper():
    h = MagicMock()
    h.connect_name = "CYFIRMA"
    h.connect_id = "connector-id"
    h.get_state.return_value = None
    h.api.work.initiate_work.return_value = "work-1"
    h.stix2_create_bundle.return_value = "bundle"
    h.send_stix2_bundle.return_value = ["bundle-1"]
    return h


@pytest.fixture
def connector(config, helper):
    with patch("connector.connector.CyfirmaClient") as client_cls, patch(
        "connector.connector.ConverterToStix"
    ) as converter_cls:
        converter_cls.return_value.tlp_marking.id = TLP_ID
        conn = CyfirmaConnector(config=config, helper=helper)
        conn._client_cls = client_cls
        conn._converter_cls = converter_cls
        yield conn


# --------------------------------------------------------------------------- #
# __init__
# --------------------------------------------------------------------------- #


def test_init_builds_client_and_converter(connector, config, helper):
    connector._client_cls.assert_called_once_with(
        helper=helper,
        base_url="https://api.cyfirma.test",
        api_key="secret",
        tailored_iocs=True,
        tailored_vulnerabilities=False,
        look_back_days=5,
    )
    connector._converter_cls.assert_called_once_with(helper, tlp_level="clear")


# --------------------------------------------------------------------------- #
# _collect_intelligence
# --------------------------------------------------------------------------- #


def test_collect_intelligence_from_dict(connector):
    connector.client.get_entities.return_value = {
        "objects": [{"id": "indicator--1"}, {"id": "vulnerability--1"}]
    }

    result = connector._collect_intelligence()

    # two entities + the TLP marking itself appended at the end
    assert len(result) == 3
    assert result[-1] is connector.converter_to_stix.tlp_marking
    assert result[0]["object_marking_refs"] == [TLP_ID]
    assert result[1]["object_marking_refs"] == [TLP_ID]


def test_collect_intelligence_from_list(connector):
    connector.client.get_entities.return_value = [{"id": "indicator--1"}]

    result = connector._collect_intelligence()

    assert len(result) == 2
    assert result[0]["object_marking_refs"] == [TLP_ID]


def test_collect_intelligence_does_not_duplicate_marking(connector):
    connector.client.get_entities.return_value = [
        {"id": "indicator--1", "object_marking_refs": [TLP_ID]}
    ]

    result = connector._collect_intelligence()

    assert result[0]["object_marking_refs"] == [TLP_ID]


def test_collect_intelligence_keeps_existing_markings(connector):
    connector.client.get_entities.return_value = [
        {"id": "indicator--1", "object_marking_refs": ["marking-definition--other"]}
    ]

    result = connector._collect_intelligence()

    assert result[0]["object_marking_refs"] == ["marking-definition--other", TLP_ID]


@pytest.mark.parametrize("entities", [[], {}, {"objects": []}, None, "unexpected"])
def test_collect_intelligence_empty_or_unsupported(connector, entities):
    connector.client.get_entities.return_value = entities

    assert connector._collect_intelligence() == []


# --------------------------------------------------------------------------- #
# process_message
# --------------------------------------------------------------------------- #


def test_process_message_first_run(connector, helper):
    connector.client.get_entities.return_value = [{"id": "indicator--1"}]

    connector.process_message()

    helper.api.work.initiate_work.assert_called_once_with(
        "connector-id", "CYFIRMA feed"
    )
    helper.stix2_create_bundle.assert_called_once()
    helper.send_stix2_bundle.assert_called_once_with(
        "bundle", work_id="work-1", cleanup_inconsistent_bundle=True
    )
    saved_state = helper.set_state.call_args.args[0]
    assert "last_run" in saved_state
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.args[0] == "work-1"
    assert "successfully run" in helper.api.work.to_processed.call_args.args[1]


def test_process_message_uses_previous_state(connector, helper):
    helper.get_state.return_value = {"last_run": "2026-01-01 00:00:00", "other": 1}
    connector.client.get_entities.return_value = [{"id": "indicator--1"}]

    connector.process_message()

    assert connector.client.last_run == "2026-01-01 00:00:00"
    saved_state = helper.set_state.call_args.args[0]
    assert saved_state["other"] == 1
    assert saved_state["last_run"] != "2026-01-01 00:00:00"


def test_process_message_state_without_last_run(connector, helper):
    helper.get_state.return_value = {"other": 1}
    connector.client.get_entities.return_value = []

    connector.process_message()

    # no "last_run" in the stored state -> treated as a first run
    saved_state = helper.set_state.call_args.args[0]
    assert saved_state["other"] == 1
    assert "last_run" in saved_state


def test_process_message_no_objects_skips_bundle(connector, helper):
    connector.client.get_entities.return_value = []

    connector.process_message()

    helper.stix2_create_bundle.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_called_once()
    helper.api.work.to_processed.assert_called_once()


def test_process_message_error_marks_work_in_error_and_raises(connector, helper):
    connector.client.get_entities.side_effect = RuntimeError("api down")

    with pytest.raises(RuntimeError, match="api down"):
        connector.process_message()

    helper.api.work.to_processed.assert_called_once()
    args, kwargs = helper.api.work.to_processed.call_args
    assert args[0] == "work-1"
    assert "Unexpected error: api down" in args[1]
    assert kwargs == {"in_error": True}
    helper.set_state.assert_not_called()


def test_process_message_error_before_work_created(connector, helper):
    helper.get_state.side_effect = RuntimeError("state unavailable")

    with pytest.raises(RuntimeError, match="state unavailable"):
        connector.process_message()

    # no work was initiated, so there is nothing to close
    helper.api.work.to_processed.assert_not_called()


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
def test_process_message_interrupt_exits_cleanly(connector, helper, exc):
    helper.api.work.initiate_work.side_effect = exc()

    with pytest.raises(SystemExit) as exit_info:
        connector.process_message()

    assert exit_info.value.code == 0
    helper.set_state.assert_not_called()


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #


def test_run_schedules_process(connector, helper):
    connector.run()

    helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=3600.0,
    )


def test_collect_intelligence_skips_marking_definitions(connector):
    feed_tlp = {"type": "marking-definition", "id": TLP_ID}
    other_marking = {"type": "marking-definition", "id": "marking-definition--other"}
    connector.client.get_entities.return_value = [
        {"type": "indicator", "id": "indicator--1"},
        feed_tlp,
        other_marking,
    ]

    result = connector._collect_intelligence()

    assert result[0]["object_marking_refs"] == [TLP_ID]
    # marking definitions are kept as-is, without markings or self-reference
    assert result[1] == {"type": "marking-definition", "id": TLP_ID}
    assert "object_marking_refs" not in result[1]
    assert "object_marking_refs" not in result[2]
