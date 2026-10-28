# pragma: no cover
# type: ignore
import copy
import json
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_enrichment._message_manager import (
    MessageManager,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    EntityOutOfScopeError,
    UnsupportedEntityError,
)
from connectors_sdk.models import AutonomousSystem, IPV4Address, Reference
from pycti import OpenCTIConnectorHelper

IP = IPV4Address(value="1.2.3.4")
RELATED = {"type": "x-opencti-text", "id": "x-opencti-text--1", "value": "t"}
NOTE = {"type": "note", "id": "note--1", "content": "c"}


def _make_message(from_playbook: bool = False) -> EnrichmentMessage:
    stix_entity = {
        "type": "ipv4-addr",
        "id": IP.id,
        "value": "1.2.3.4",
        "x_opencti_score": 10,
        "x_opencti_labels": ["original"],
    }
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {"id": "octi-id", "entity_type": "IPv4-Addr"},
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity, RELATED],
            "from_playbook": from_playbook,
        }
    )


def _make_manager() -> tuple[MessageManager, MagicMock]:
    helper = MagicMock()
    helper.stix2_create_bundle.side_effect = OpenCTIConnectorHelper.stix2_create_bundle
    return MessageManager(helper), helper


def _sent_objects(helper: MagicMock) -> list[dict]:
    [call] = helper.send_stix2_bundle.call_args_list
    return json.loads(call.args[0])["objects"]


class TestSend:
    def test_sends_the_bundle_and_sets_the_outcome(self):
        manager, helper = _make_manager()

        with manager.handle(_make_message()):
            manager.send([NOTE])

        assert manager.outcome == "Entity enriched with 1 objects"
        assert helper.send_stix2_bundle.call_args.kwargs == {
            "cleanup_inconsistent_bundle": True
        }

    def test_adds_new_objects_after_the_original_ones(self):
        manager, helper = _make_manager()
        asn = AutonomousSystem(number=64500)

        with manager.handle(_make_message()):
            manager.send([asn])

        assert [obj["id"] for obj in _sent_objects(helper)] == [
            IP.id,
            RELATED["id"],
            asn.id,
        ]

    def test_replaces_an_original_object_with_the_same_id(self):
        manager, helper = _make_manager()

        with manager.handle(_make_message()):
            manager.send([IPV4Address(value="1.2.3.4", score=80)])

        sent = _sent_objects(helper)
        assert [obj["id"] for obj in sent] == [IP.id, RELATED["id"]]
        assert sent[0]["x_opencti_score"] == 80

    def test_accepts_stix2_objects_and_stix_dicts_and_ignores_references(self):
        manager, helper = _make_manager()
        asn = AutonomousSystem(number=64500).to_stix2_object()

        with manager.handle(_make_message()):
            manager.send([Reference(id=IP.id), asn, NOTE])

        assert [obj["id"] for obj in _sent_objects(helper)] == [
            IP.id,
            RELATED["id"],
            asn.id,
            "note--1",
        ]

    def test_sends_nothing_without_new_objects(self):
        manager, helper = _make_manager()

        with manager.handle(_make_message()):
            manager.send([])

        assert manager.outcome == "No enrichment data found"
        helper.send_stix2_bundle.assert_not_called()

    def test_refuses_to_send_twice(self):
        manager, helper = _make_manager()

        with pytest.raises(RuntimeError, match="already sent"):
            with manager.handle(_make_message(from_playbook=True)):
                manager.send([NOTE])
                manager.send([NOTE])

        helper.send_stix2_bundle.assert_called_once()


class TestOriginalBundle:
    def test_sends_the_original_bundle_back_in_a_playbook_without_data(self):
        manager, helper = _make_manager()
        message = _make_message(from_playbook=True)

        with manager.handle(message):
            manager.send([])

        assert _sent_objects(helper) == message.stix_objects

    def test_sends_the_original_bundle_as_received(self):
        manager, helper = _make_manager()
        message = _make_message(from_playbook=True)
        original = copy.deepcopy(message.stix_objects)

        with manager.handle(message):
            # A processor changing the message before skipping
            message.stix_objects[0]["x_opencti_labels"].append("changed")
            raise UnsupportedEntityError("No processor can process this entity")

        assert _sent_objects(helper) == original

    def test_handles_each_message_on_its_own(self):
        manager, helper = _make_manager()

        with manager.handle(_make_message(from_playbook=True)):
            manager.send([NOTE])
        with manager.handle(_make_message(from_playbook=True)):
            raise UnsupportedEntityError("No processor can process this entity")

        assert helper.send_stix2_bundle.call_count == 2
        assert manager.outcome == "No processor can process this entity"


class TestSkipAndFailure:
    @pytest.mark.parametrize("from_playbook", [False, True])
    def test_stops_an_unsupported_entity_error(self, from_playbook):
        manager, helper = _make_manager()

        with manager.handle(_make_message(from_playbook)):
            raise UnsupportedEntityError("No processor can process this entity")

        assert manager.outcome == "No processor can process this entity"
        assert helper.send_stix2_bundle.call_count == (1 if from_playbook else 0)

    def test_skips_an_entity_out_of_scope_in_a_playbook(self):
        manager, helper = _make_manager()

        with manager.handle(_make_message(from_playbook=True)):
            raise EntityOutOfScopeError("Entity type Url is out of scope")

        assert manager.outcome == "Entity type Url is out of scope"
        helper.send_stix2_bundle.assert_called_once()

    def test_raises_an_entity_out_of_scope_again_outside_a_playbook(self, caplog):
        manager, helper = _make_manager()

        with pytest.raises(EntityOutOfScopeError, match="out of scope"):
            with manager.handle(_make_message(from_playbook=False)):
                raise EntityOutOfScopeError("Entity type Url is out of scope")

        helper.send_stix2_bundle.assert_not_called()
        assert [record.getMessage() for record in caplog.records] == [
            "Enrichment failed"
        ]

    def test_skip_logs_a_failure_to_send_the_original_bundle(self, caplog):
        manager, helper = _make_manager()
        helper.send_stix2_bundle.side_effect = ConnectionError("API down")

        with manager.handle(_make_message(from_playbook=True)):
            raise UnsupportedEntityError("No processor can process this entity")

        assert manager.outcome == "No processor can process this entity"
        assert [record.getMessage() for record in caplog.records] == [
            "Failed to send the original bundle back"
        ]

    def test_failure_sends_the_original_bundle_in_a_playbook(self, caplog):
        manager, helper = _make_manager()
        message = _make_message(from_playbook=True)

        with pytest.raises(ValueError, match="boom"):
            with manager.handle(message):
                raise ValueError("boom")

        assert _sent_objects(helper) == message.stix_objects
        assert [record.getMessage() for record in caplog.records] == [
            "Enrichment failed"
        ]

    @pytest.mark.parametrize("from_playbook", [False, True])
    def test_lets_a_keyboard_interrupt_stop_the_connector(self, from_playbook):
        manager, helper = _make_manager()

        with pytest.raises(KeyboardInterrupt):
            with manager.handle(_make_message(from_playbook)):
                raise KeyboardInterrupt

        # The `finally` block still sends the original bundle back in a playbook
        assert helper.send_stix2_bundle.call_count == (1 if from_playbook else 0)


def test_entity_out_of_scope_error_is_an_unsupported_entity_error():
    assert issubclass(EntityOutOfScopeError, UnsupportedEntityError)
