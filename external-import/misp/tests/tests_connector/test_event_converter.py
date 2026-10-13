from unittest.mock import MagicMock

import pytest
from api_client.models import EventRestSearchListItem
from connector.use_cases import convert_event
from connector.use_cases.convert_event import (
    DEFAULT_THREAT_LEVEL_SCORE_MAPPING,
    EventConverter,
    event_threat_level_to_opencti_score,
)


@pytest.mark.parametrize(
    "threat_level, expected",
    [
        ("1", 90),
        ("2", 60),
        ("3", 30),
        ("4", 50),
    ],
)
def test_event_threat_level_to_opencti_score_default_mapping(threat_level, expected):
    """When called without an explicit mapping, the function reproduces the
    legacy hard-coded behavior (1=90, 2=60, 3=30, 4=50) so upgrading users
    who do not configure ``MISP_THREAT_LEVEL_SCORE_MAPPING`` keep getting
    identical scores.
    """
    assert event_threat_level_to_opencti_score(threat_level) == expected


def test_event_threat_level_to_opencti_score_unknown_value_falls_back_to_level_4():
    """MISP can return a ``threat_level_id`` outside ``[1, 4]`` (older
    instances, custom forks). Such values must resolve to the score
    associated with level ``"4"`` (Undefined) rather than raising.
    """
    assert event_threat_level_to_opencti_score("5") == 50
    assert event_threat_level_to_opencti_score("99") == 50


def test_event_threat_level_to_opencti_score_uses_custom_mapping():
    """The function honors the mapping provided by the caller, both for
    known levels and for the fallback (level ``"4"``).
    """
    mapping = {"1": 100, "2": 70, "3": 40, "4": 10}
    assert event_threat_level_to_opencti_score("1", mapping) == 100
    assert event_threat_level_to_opencti_score("2", mapping) == 70
    assert event_threat_level_to_opencti_score("3", mapping) == 40
    assert event_threat_level_to_opencti_score("4", mapping) == 10
    # Unknown threat-level resolves to the "Undefined" score.
    assert event_threat_level_to_opencti_score("foo", mapping) == 10


def test_default_threat_level_score_mapping_matches_legacy_behavior():
    """The module-level default mapping must mirror the historic
    hard-coded values so the behavior is preserved when no override
    is supplied at runtime.
    """
    assert DEFAULT_THREAT_LEVEL_SCORE_MAPPING == {
        "1": 90,
        "2": 60,
        "3": 30,
        "4": 50,
    }


def _make_event_with_object_reference() -> EventRestSearchListItem:
    """Build an event with an Object containing an ObjectReference, which is
    the payload that used to crash `EventConverter.process` with a
    `TypeError: 'ObjectItemObjectReference' object is not subscriptable`.
    """
    return EventRestSearchListItem.model_validate(
        {
            "Event": {
                "id": "1",
                "uuid": "00000000-0000-0000-0000-000000000001",
                "info": "Test event",
                "date": "2026-01-15",
                "timestamp": "1768521600",
                "threat_level_id": "2",
                "Orgc": {"name": "TestOrg"},
                "Object": [
                    {
                        "id": "10",
                        "uuid": "10000000-0000-0000-0000-000000000000",
                        "name": "source-object",
                        "meta-category": "misc",
                        "ObjectReference": [
                            {
                                "source_uuid": "10000000-0000-0000-0000-000000000000",
                                "referenced_uuid": "20000000-0000-0000-0000-000000000000",
                                "relationship_type": "related-to",
                                "comment": "Test comment",
                            }
                        ],
                    },
                    {
                        "id": "20",
                        "uuid": "20000000-0000-0000-0000-000000000000",
                        "name": "target-object",
                        "meta-category": "misc",
                    },
                ],
            }
        }
    )


def test_process_object_reference_uses_attribute_access(monkeypatch):
    """Regression test for issue #7261: `EventConverter.process` must read
    `relationship_type`/`comment` from `ObjectItemObjectReference` using
    attribute access, not dictionary-style subscript access, since it is a
    typed (pydantic) object, not a dict.
    """
    # Given an event with an Object Reference between two objects that
    # resolve to STIX entities
    event = _make_event_with_object_reference()

    logger = MagicMock()
    converter = EventConverter(
        logger=logger,
        external_reference_base_url="http://test.com",
    )

    fake_source = {
        "entity": {"id": "identity--10000000-0000-4000-8000-000000000000"},
        "type": "identity",
    }
    fake_target = {
        "entity": {"id": "identity--20000000-0000-4000-8000-000000000000"},
        "type": "identity",
    }

    def fake_find_type_by_uuid(uuid, stix_objects):
        if uuid == "10000000-0000-0000-0000-000000000000":
            return fake_source
        if uuid == "20000000-0000-0000-0000-000000000000":
            return fake_target
        return None

    monkeypatch.setattr(convert_event, "find_type_by_uuid", fake_find_type_by_uuid)

    # When processing the event
    _, _, stix_objects = converter.process(event)

    # Then a relationship is created with the relationship_type/comment
    # correctly read via attribute access, and no exception is raised
    relationships = [
        obj
        for obj in stix_objects
        if obj.get("type") == "relationship"
        and obj["source_ref"] == fake_source["entity"]["id"]
        and obj["target_ref"] == fake_target["entity"]["id"]
    ]
    assert len(relationships) == 1
    assert "Original Relationship: related-to" in relationships[0]["description"]
    assert "Comment: Test comment" in relationships[0]["description"]


def test_process_object_reference_error_is_caught_and_logged(monkeypatch):
    """A malformed/unexpected object reference must not interrupt the whole
    event processing: the error is logged and the event conversion
    continues instead of raising.
    """
    # Given an event with an object reference, but `find_type_by_uuid`
    # raising an unexpected error while resolving it
    event = _make_event_with_object_reference()

    logger = MagicMock()
    converter = EventConverter(
        logger=logger,
        external_reference_base_url="http://test.com",
    )

    def broken_find_type_by_uuid(uuid, stix_objects):
        raise RuntimeError("boom")

    monkeypatch.setattr(convert_event, "find_type_by_uuid", broken_find_type_by_uuid)

    # When processing the event
    # Then no exception propagates and the error is logged as a warning
    converter.process(event)

    assert logger.warning.called
