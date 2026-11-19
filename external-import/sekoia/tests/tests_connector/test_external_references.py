from unittest.mock import MagicMock, call

import pytest
from src.connector.sekoia import SekoiaConnector

INDICATOR_ID = "indicator--89c4436d-5e9b-4a19-aecd-23611e04a1c4"
MALWARE_ID = "malware--0f3e5d4a-8c1b-4f6e-9a2d-7b5c3e1f0a9d"
RELATIONSHIP_ID = "relationship--5e2a1c7b-3d4f-4a8e-b9c6-1f0e2d3c4b5a"
SEKOIA_REFERENCE = {
    "source_name": "Sekoia.io",
    "url": f"https://app.sekoia.io/intelligence/objects/{INDICATOR_ID}",
}


def sandbox_references(count: int) -> list[dict]:
    return [
        {"source_name": "Triage Sandbox", "url": f"https://tria.ge/241104-{i:08d}"}
        for i in range(count)
    ]


def other_references(count: int) -> list[dict]:
    return [
        {"source_name": "Other source", "url": f"https://example.com/report/{i}"}
        for i in range(count)
    ]


def make_connector(max_external_references: int | None) -> SekoiaConnector:
    """Build the connector with mocked settings and helper (no network call)."""
    config = MagicMock()
    config.sekoia.max_external_references = max_external_references
    config.sekoia.confidence_score = None
    config.sekoia.send_confidence = True
    config.sekoia.create_observables = True
    config.sekoia.import_source_list = False
    config.sekoia.import_ioc_relationships = True
    connector = SekoiaConnector(config, MagicMock())
    # Forget the logs written while the connector loads its data sets.
    connector.helper.connector_logger.reset_mock()
    return connector


def test_limit_external_references_should_do_nothing_without_limit():
    connector = make_connector(max_external_references=None)
    references = sandbox_references(100) + [SEKOIA_REFERENCE]
    items = [{"id": INDICATOR_ID, "external_references": list(references)}]

    connector._limit_external_references(items)

    assert items[0]["external_references"] == references


@pytest.mark.parametrize("count", [0, 4, 5])
def test_limit_external_references_should_keep_objects_under_the_limit(count):
    connector = make_connector(max_external_references=5)
    references = sandbox_references(count)
    items = [{"id": INDICATOR_ID, "external_references": list(references)}]

    connector._limit_external_references(items)

    assert items[0]["external_references"] == references
    connector.helper.connector_logger.info.assert_not_called()


def test_limit_external_references_should_ignore_objects_without_references():
    connector = make_connector(max_external_references=5)
    items = [{"id": RELATIONSHIP_ID}]

    connector._limit_external_references(items)

    assert items == [{"id": RELATIONSHIP_ID}]


def test_limit_external_references_should_keep_sekoia_then_the_first_others():
    # The Sekoia.io reference is last in the list, as the connector adds it.
    # It is still kept, and it counts toward the limit.
    # The other references keep the API order, whatever their source.
    connector = make_connector(max_external_references=4)
    sandbox = sandbox_references(10)
    others = other_references(2)
    items = [
        {
            "id": INDICATOR_ID,
            "external_references": sandbox[:2]
            + [others[0]]
            + sandbox[2:]
            + [others[1], SEKOIA_REFERENCE],
        }
    ]

    connector._limit_external_references(items)

    assert items[0]["external_references"] == [
        SEKOIA_REFERENCE,
        sandbox[0],
        sandbox[1],
        others[0],
    ]


def test_limit_external_references_should_log_each_truncated_object():
    connector = make_connector(max_external_references=3)
    items = [
        {"id": INDICATOR_ID, "external_references": sandbox_references(10)},
        {"id": MALWARE_ID, "external_references": sandbox_references(4)},
        {"id": RELATIONSHIP_ID, "external_references": sandbox_references(2)},
    ]

    connector._limit_external_references(items)

    assert connector.helper.connector_logger.info.call_args_list == [
        call(
            "External references truncated",
            {
                "object_id": INDICATOR_ID,
                "max_external_references": 3,
                "references_count": 10,
                "removed_references_count": 7,
            },
        ),
        call(
            "External references truncated",
            {
                "object_id": MALWARE_ID,
                "max_external_references": 3,
                "references_count": 4,
                "removed_references_count": 1,
            },
        ),
    ]


def test_run_should_limit_external_references_on_every_object_sent():
    connector = make_connector(max_external_references=3)
    indicator = {
        "type": "indicator",
        "id": INDICATOR_ID,
        "pattern": "[file:hashes.'SHA-256' = 'abc']",
        "external_references": sandbox_references(4284) + other_references(1),
    }
    malware = {
        "type": "malware",
        "id": MALWARE_ID,
        "name": "RedLine",
        "external_references": sandbox_references(20),
    }
    relationship = {
        "type": "relationship",
        "id": RELATIONSHIP_ID,
        "relationship_type": "indicates",
        "source_ref": INDICATOR_ID,
        "target_ref": MALWARE_ID,
    }

    def send_request(url, params=None, binary=False):
        if url == connector.get_collection_url():
            return {"next_cursor": "next-cursor", "items": [indicator]}
        if url == connector.get_relationship(INDICATOR_ID):
            return {
                "items": [{"related_object": malware, "relationship": relationship}]
            }
        raise AssertionError(f"Unexpected request: {url}")

    connector._send_request = send_request

    cursor = connector._run("cursor", "work-id")

    assert cursor == "next-cursor"
    sent_items = connector.helper.stix2_create_bundle.call_args.args[0]
    sent_by_id = {item["id"]: item for item in sent_items}
    assert sent_by_id[INDICATOR_ID]["external_references"] == [
        SEKOIA_REFERENCE,
        *sandbox_references(2),
    ]
    assert sent_by_id[MALWARE_ID]["external_references"] == sandbox_references(3)
    assert "external_references" not in sent_by_id[RELATIONSHIP_ID]
