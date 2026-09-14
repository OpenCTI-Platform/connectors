import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, MalantaAttributionConnector

INDICATOR_ID = "indicator--0a95e840-5dab-4a71-a74f-5c5ed91a6a76"
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
# OpenCTI normalises an identity's id from its name; this is what the stream carries
# for `Malanta.ai`, and what `pycti.Identity.generate_id` produces.
MALANTA_AUTHOR = "identity--816d93c2-009c-58c9-9bb0-613398a3c6de"
OTHER_AUTHOR = "identity--11111111-2222-3333-4444-555555555555"

BASE_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "Malanta Attribution",
        "scope": "indicator",
        "log_level": "error",
        "live_stream_id": "live",
    },
}


def build_settings(overrides: dict[str, Any] | None = None) -> ConnectorSettings:
    settings_dict = json.loads(json.dumps(BASE_SETTINGS))
    if overrides:
        settings_dict["malanta_attribution"] = overrides

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.connect_live_stream_id = "live"
    helper.stix2_create_bundle.side_effect = lambda objects: {"objects": objects}
    return helper


@pytest.fixture
def connector(helper):
    return MalantaAttributionConnector(config=build_settings(), helper=helper)


def message(event: str, data: dict[str, Any]) -> SimpleNamespace:
    """Build a stream message shaped like the ones pycti delivers."""
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


def indicator(**overrides: Any) -> dict[str, Any]:
    payload = {
        "id": INDICATOR_ID,
        "type": "indicator",
        "created_by_ref": MALANTA_AUTHOR,
        "confidence": 73,
        "labels": ["IOC", "apt:APT38", "domain", "source:lazarus.day"],
        "object_marking_refs": [TLP_AMBER],
    }
    payload.update(overrides)
    return payload


def sent_objects(helper) -> list[Any]:
    """Return the objects passed to the last send_stix2_bundle call."""
    assert helper.send_stix2_bundle.called
    return helper.stix2_create_bundle.call_args[0][0]


@pytest.mark.parametrize("event", ["create", "update"])
def test_tagged_indicator_produces_attribution(connector, helper, event):
    connector.process_message(message(event, indicator()))

    types = [obj.type for obj in sent_objects(helper)]
    assert types.count("intrusion-set") == 1
    assert types.count("relationship") == 1


def test_untagged_indicator_sends_nothing(connector, helper):
    """The large majority of the feed carries no `apt:` labels."""
    connector.process_message(
        message("create", indicator(labels=["IOPA", "domain", "source:malanta"]))
    )
    helper.send_stix2_bundle.assert_not_called()


def test_indicator_with_no_labels_sends_nothing(connector, helper):
    connector.process_message(message("create", indicator(labels=[])))
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "entity_type",
    ["intrusion-set", "relationship", "identity", "marking-definition", "domain-name"],
)
def test_non_indicator_events_are_ignored(connector, helper, entity_type):
    """Feedback-loop guard.

    The connector emits Intrusion Sets and relationships. If it reacted to those,
    it would trigger itself indefinitely.
    """
    connector.process_message(
        message("create", {"id": f"{entity_type}--x", "type": entity_type})
    )
    helper.send_stix2_bundle.assert_not_called()


def test_delete_events_are_ignored(connector, helper):
    """v1 only adds attribution; it never revokes it."""
    connector.process_message(message("delete", indicator()))
    helper.send_stix2_bundle.assert_not_called()


def test_malformed_message_does_not_raise(connector, helper):
    """A bad payload must not kill the stream."""
    connector.process_message(SimpleNamespace(event="create", data="not-json"))
    helper.send_stix2_bundle.assert_not_called()
    assert helper.connector_logger.error.called


def test_missing_stream_id_is_reported_not_raised(helper):
    """A misconfigured stream id is logged rather than crashing the callback."""
    helper.connect_live_stream_id = None
    connector = MalantaAttributionConnector(config=build_settings(), helper=helper)

    connector.process_message(message("create", indicator()))

    helper.send_stix2_bundle.assert_not_called()
    assert helper.connector_logger.error.called


def test_check_stream_id_raises_on_placeholder(helper):
    helper.connect_live_stream_id = "ChangeMe"
    connector = MalantaAttributionConnector(config=build_settings(), helper=helper)
    with pytest.raises(ValueError):
        connector.check_stream_id()


def test_repeated_events_produce_identical_ids(connector, helper):
    """Idempotency: replay must upsert, not duplicate."""
    connector.process_message(message("create", indicator()))
    first = {obj.id for obj in sent_objects(helper)}

    connector.process_message(message("update", indicator()))
    second = {obj.id for obj in sent_objects(helper)}

    assert first == second


def test_comma_joined_actor_token_is_split(connector, helper):
    """Upstream data bug `apt:APT17,APT5` must not create one merged entity."""
    connector.process_message(message("create", indicator(labels=["apt:APT17,APT5"])))

    names = {o.name for o in sent_objects(helper) if o.type == "intrusion-set"}
    assert names == {"APT17", "APT5"}


def test_min_confidence_skips_low_confidence_indicators(helper):
    connector = MalantaAttributionConnector(
        config=build_settings({"min_confidence": 80}), helper=helper
    )
    connector.process_message(message("create", indicator(confidence=73)))
    helper.send_stix2_bundle.assert_not_called()


def test_min_confidence_allows_indicators_at_threshold(helper):
    connector = MalantaAttributionConnector(
        config=build_settings({"min_confidence": 70}), helper=helper
    )
    connector.process_message(message("create", indicator(confidence=73)))
    helper.send_stix2_bundle.assert_called_once()


def test_create_intrusion_sets_disabled_emits_relationships_only(helper):
    connector = MalantaAttributionConnector(
        config=build_settings({"create_intrusion_sets": False}), helper=helper
    )
    connector.process_message(message("create", indicator()))

    types = [obj.type for obj in sent_objects(helper)]
    assert "intrusion-set" not in types
    assert types.count("relationship") == 1


def test_custom_label_prefix_is_honoured(helper):
    connector = MalantaAttributionConnector(
        config=build_settings({"label_prefix": "actor:"}), helper=helper
    )
    connector.process_message(
        message("create", indicator(labels=["actor:APT44", "apt:IGNORED"]))
    )

    names = {o.name for o in sent_objects(helper) if o.type == "intrusion-set"}
    assert names == {"APT44"}


# --- provenance filtering ------------------------------------------------------


def test_indicator_from_another_source_is_ignored(connector, helper):
    """Another feed's `apt:` labels must not be credited to Malanta.

    `apt:` is a plausible namespace for any threat-intel source. Without this
    guard, a MISP or AlienVault indicator would produce Intrusion Sets stamped
    `created_by_ref = Malanta.ai`.
    """
    connector.process_message(message("create", indicator(created_by_ref=OTHER_AUTHOR)))
    helper.send_stix2_bundle.assert_not_called()


def test_indicator_without_author_is_ignored(connector, helper):
    """Provenance cannot be confirmed, so the indicator is skipped."""
    payload = indicator()
    payload.pop("created_by_ref")
    connector.process_message(message("create", payload))
    helper.send_stix2_bundle.assert_not_called()


def test_indicator_from_expected_source_is_processed(connector, helper):
    connector.process_message(message("create", indicator()))
    helper.send_stix2_bundle.assert_called_once()


def test_empty_source_author_disables_provenance_filtering(helper):
    """Operators integrating several sources deliberately can opt out."""
    connector = MalantaAttributionConnector(
        config=build_settings({"source_author": ""}), helper=helper
    )
    connector.process_message(message("create", indicator(created_by_ref=OTHER_AUTHOR)))
    helper.send_stix2_bundle.assert_called_once()


def test_source_author_is_matched_by_normalised_identity_id(helper):
    """The guard derives the id from the name, matching what the stream sends."""
    connector = MalantaAttributionConnector(
        config=build_settings({"source_author": "Malanta.ai"}), helper=helper
    )
    assert connector.expected_author_ref == MALANTA_AUTHOR


def test_custom_source_author_changes_the_expected_id(helper):
    connector = MalantaAttributionConnector(
        config=build_settings({"source_author": "Some Other Vendor"}), helper=helper
    )
    assert connector.expected_author_ref != MALANTA_AUTHOR
    connector.process_message(message("create", indicator()))
    helper.send_stix2_bundle.assert_not_called()
