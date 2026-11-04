# pragma: no cover
# type: ignore
import copy
import json
import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_enrichment._bundle_manager import (
    BundleManager,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    InvalidEnrichmentMessageError,
    UnsupportedEntityError,
)
from connectors_sdk.models import AutonomousSystem, IPV4Address, Reference
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError

IP = IPV4Address(value="1.2.3.4")
RELATED = {"type": "x-opencti-text", "id": "x-opencti-text--1", "value": "t"}
NOTE = {"type": "note", "id": "note--1", "content": "c"}


def _make_data() -> dict[str, Any]:
    stix_entity = {
        "type": "ipv4-addr",
        "id": IP.id,
        "value": "1.2.3.4",
        "x_opencti_score": 10,
        "x_opencti_labels": ["original"],
    }
    return {
        "entity_id": IP.id,
        "enrichment_entity": {"id": "octi-id", "entity_type": "IPv4-Addr"},
        "stix_entity": stix_entity,
        "stix_objects": [copy.deepcopy(stix_entity), RELATED],
    }


def _make_manager(
    from_playbook: bool = False, data: dict[str, Any] | None = None
) -> tuple[BundleManager, MagicMock]:
    helper = MagicMock()
    helper.playbook = {"playbook_id": "playbook--1"} if from_playbook else None
    helper.stix2_create_bundle.side_effect = OpenCTIConnectorHelper.stix2_create_bundle
    return BundleManager(helper, data or _make_data()), helper


def _make_message(
    manager: BundleManager, data: dict[str, Any] | None = None
) -> EnrichmentMessage:
    return EnrichmentMessage.model_validate(
        {**(data or _make_data()), "from_playbook": manager._from_playbook}
    )


def _sent_objects(helper: MagicMock) -> list[dict]:
    [call] = helper.send_stix2_bundle.call_args_list
    return json.loads(call.args[0])["objects"]


class TestInvalidMessage:
    def test_logs_and_raises_an_invalid_message_without_sending(self, caplog):
        manager, helper = _make_manager()

        with pytest.raises(InvalidEnrichmentMessageError):
            with manager:
                raise InvalidEnrichmentMessageError("Invalid enrichment message")

        helper.send_stix2_bundle.assert_not_called()
        assert [
            (record.getMessage(), record.attributes) for record in caplog.records
        ] == [("Invalid enrichment message", {"entity_id": IP.id})]

    def test_sends_the_objects_received_back_in_a_playbook(self):
        data = _make_data()
        manager, helper = _make_manager(from_playbook=True, data=data)

        with pytest.raises(InvalidEnrichmentMessageError):
            with manager:
                raise InvalidEnrichmentMessageError("Invalid enrichment message")

        assert _sent_objects(helper) == data["stix_objects"]

    def test_sends_nothing_back_without_objects_received(self):
        data = _make_data()
        data["stix_objects"] = None
        manager, helper = _make_manager(from_playbook=True, data=data)

        with pytest.raises(InvalidEnrichmentMessageError):
            with manager:
                raise InvalidEnrichmentMessageError("Invalid enrichment message")

        helper.send_stix2_bundle.assert_not_called()

    def test_logs_a_validation_error_of_a_processor_as_an_enrichment_failure(
        self, caplog
    ):
        manager, _ = _make_manager()

        with pytest.raises(ValidationError):
            with manager:
                # e.g. a processor building an SDK model with an invalid value
                IPV4Address(value="not an ip")

        assert [record.getMessage() for record in caplog.records] == [
            "Enrichment failed"
        ]


class TestLogMetadata:
    def test_uses_the_message_once_given(self, caplog):
        manager, _ = _make_manager()

        with pytest.raises(ValueError):
            with manager:
                manager.message = _make_message(manager)
                raise ValueError("boom")

        assert [record.attributes for record in caplog.records] == [
            {
                "octi_id": "octi-id",
                "octi_entity_type": "IPv4-Addr",
                "from_playbook": False,
            }
        ]


class TestSend:
    def test_sends_the_bundle_and_sets_the_outcome(self, caplog):
        caplog.set_level(logging.INFO)
        manager, helper = _make_manager()

        with manager:
            manager.objects = [NOTE]

        assert manager.outcome == "Entity enriched with 1 objects"
        assert helper.send_stix2_bundle.call_args.kwargs == {
            "cleanup_inconsistent_bundle": True
        }
        assert "Entity enriched" in [r.getMessage() for r in caplog.records]

    def test_adds_new_objects_after_the_original_ones(self):
        manager, helper = _make_manager()
        asn = AutonomousSystem(number=64500)

        with manager:
            manager.objects = [asn]

        assert [obj["id"] for obj in _sent_objects(helper)] == [
            IP.id,
            RELATED["id"],
            asn.id,
        ]

    def test_replaces_an_original_object_with_the_same_id(self):
        manager, helper = _make_manager()

        with manager:
            manager.objects = [IPV4Address(value="1.2.3.4", score=80)]

        sent = _sent_objects(helper)
        assert [obj["id"] for obj in sent] == [IP.id, RELATED["id"]]
        assert sent[0]["x_opencti_score"] == 80

    def test_accepts_stix2_objects_and_stix_dicts_and_ignores_references(self):
        manager, helper = _make_manager()
        asn = AutonomousSystem(number=64500).to_stix2_object()

        with manager:
            manager.objects = [Reference(id=IP.id), asn, NOTE]

        assert [obj["id"] for obj in _sent_objects(helper)] == [
            IP.id,
            RELATED["id"],
            asn.id,
            "note--1",
        ]

    def test_sends_nothing_without_new_objects(self, caplog):
        caplog.set_level(logging.INFO)
        manager, helper = _make_manager()

        with manager:
            manager.objects = []

        assert manager.outcome == "No enrichment data found"
        helper.send_stix2_bundle.assert_not_called()
        assert "No enrichment data found" in [r.getMessage() for r in caplog.records]

    def test_sends_one_bundle_when_the_block_ends(self):
        manager, helper = _make_manager(from_playbook=True)

        with manager:
            manager.objects = [NOTE]
            helper.send_stix2_bundle.assert_not_called()

        helper.send_stix2_bundle.assert_called_once()

    def test_send_failure_is_raised_without_sending_the_original_bundle(self, caplog):
        manager, helper = _make_manager(from_playbook=True)
        helper.send_stix2_bundle.side_effect = TimeoutError("request timed out")

        with pytest.raises(TimeoutError, match="request timed out"):
            with manager:
                manager.objects = [NOTE]

        helper.send_stix2_bundle.assert_called_once()
        assert [record.getMessage() for record in caplog.records] == [
            "Enrichment failed"
        ]

    def test_failure_to_build_the_bundle_sends_the_original_bundle(self):
        data = _make_data()
        manager, helper = _make_manager(from_playbook=True, data=data)
        helper.stix2_create_bundle.side_effect = [
            TypeError("not JSON serializable"),
            OpenCTIConnectorHelper.stix2_create_bundle(data["stix_objects"]),
        ]

        with pytest.raises(TypeError, match="not JSON serializable"):
            with manager:
                manager.objects = [NOTE]

        assert _sent_objects(helper) == data["stix_objects"]


class TestOriginalBundle:
    def test_sends_the_original_bundle_back_in_a_playbook_without_data(self):
        data = _make_data()
        manager, helper = _make_manager(from_playbook=True, data=data)

        with manager:
            manager.objects = []

        assert _sent_objects(helper) == data["stix_objects"]

    def test_sends_the_original_bundle_as_received(self):
        data = _make_data()
        original = copy.deepcopy(data["stix_objects"])
        manager, helper = _make_manager(from_playbook=True, data=data)

        with manager:
            message = _make_message(manager, data)
            # A processor changing the message before skipping
            message.stix_objects[0]["x_opencti_labels"].append("changed")
            raise UnsupportedEntityError("No processor can process this entity")

        assert _sent_objects(helper) == original


class TestSkipAndFailure:
    @pytest.mark.parametrize("from_playbook", [False, True])
    def test_stops_an_unsupported_entity_error(self, from_playbook):
        manager, helper = _make_manager(from_playbook)

        with manager:
            raise UnsupportedEntityError("No processor can process this entity")

        assert manager.outcome == "No processor can process this entity"
        assert helper.send_stix2_bundle.call_count == (1 if from_playbook else 0)

    def test_skip_logs_a_failure_to_send_the_original_bundle(self, caplog):
        manager, helper = _make_manager(from_playbook=True)
        helper.send_stix2_bundle.side_effect = ConnectionError("API down")

        with manager:
            raise UnsupportedEntityError("No processor can process this entity")

        assert manager.outcome == "No processor can process this entity"
        assert [record.getMessage() for record in caplog.records] == [
            "Failed to send the original bundle back"
        ]

    def test_failure_sends_the_original_bundle_in_a_playbook(self, caplog):
        data = _make_data()
        manager, helper = _make_manager(from_playbook=True, data=data)

        with pytest.raises(ValueError, match="boom"):
            with manager:
                raise ValueError("boom")

        assert _sent_objects(helper) == data["stix_objects"]
        assert [record.getMessage() for record in caplog.records] == [
            "Enrichment failed"
        ]

    @pytest.mark.parametrize("from_playbook", [False, True])
    def test_lets_a_keyboard_interrupt_stop_the_connector(self, from_playbook):
        manager, helper = _make_manager(from_playbook)

        with pytest.raises(KeyboardInterrupt):
            with manager:
                raise KeyboardInterrupt

        # The `finally` block still sends the original bundle back in a playbook
        assert helper.send_stix2_bundle.call_count == (1 if from_playbook else 0)
