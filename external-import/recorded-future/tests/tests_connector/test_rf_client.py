from unittest.mock import MagicMock

import requests
from rflib.rf_client import ENTITY_MATCH_PATH, LINKS_PATH, RFClient


def _build_client():
    helper = MagicMock()
    client = RFClient(token="test-token", helper=helper)
    client.session = MagicMock()
    return client


def _response(data):
    response = MagicMock()
    response.json.return_value = {"data": data}
    return response


# Scenario: entities are enriched in batches of 100 and all results are aggregated
def test_get_entities_links_processes_all_entities_in_batches_of_100():
    client = _build_client()
    entities_id = [f"id-{i}" for i in range(250)]
    client.session.post.side_effect = [
        _response([{"entity": {"id": "batch-0"}, "links": []}]),
        _response([{"entity": {"id": "batch-1"}, "links": []}]),
        _response([{"entity": {"id": "batch-2"}, "links": []}]),
    ]

    result = client.get_entities_links(entities_id)

    assert client.session.post.call_count == 3
    sent_batches = [
        call.kwargs["json"]["entities"] for call in client.session.post.call_args_list
    ]
    assert [len(batch) for batch in sent_batches] == [100, 100, 50]
    assert sent_batches[0] == entities_id[:100]
    assert sent_batches[2] == entities_id[200:]
    assert result == [
        {"entity": {"id": "batch-0"}, "links": []},
        {"entity": {"id": "batch-1"}, "links": []},
        {"entity": {"id": "batch-2"}, "links": []},
    ]


# Scenario: a single request is made when there are 100 or fewer entities
def test_get_entities_links_single_batch_below_limit():
    client = _build_client()
    entities_id = ["id-0", "id-1", "id-2"]
    client.session.post.return_value = _response([{"entity": {"id": "id-0"}}])

    result = client.get_entities_links(entities_id)

    client.session.post.assert_called_once_with(
        LINKS_PATH, json={"entities": entities_id}
    )
    assert result == [{"entity": {"id": "id-0"}}]


# Scenario: aliases combine well-known common names and the full alias list (issue #7118)
def test_get_entity_aliases_combines_common_names_and_aliases():
    client = _build_client()
    client.session.get.return_value = _response(
        {
            "id": "entity-1",
            "type": "Organization",
            "attributes": {
                "name": "APT28",
                "common_names": ["Fancy Bear"],
                "alias": ["Fancy Bear", "Sofacy", ""],
                "is_threat_actor": True,
            },
        }
    )

    aliases = client.get_entity_aliases("entity-1")

    client.session.get.assert_called_once_with(f"{ENTITY_MATCH_PATH}/entity-1")
    # Common names first, deduplicated, empty values removed
    assert aliases == ["Fancy Bear", "Sofacy"]


# Scenario: an entity without alias data returns an empty list (issue #7118)
def test_get_entity_aliases_returns_empty_list_when_no_alias():
    client = _build_client()
    client.session.get.return_value = _response(
        {
            "id": "entity-2",
            "type": "Person",
            "attributes": {
                "name": "Lone Wolf",
                "common_names": [],
                "alias": [],
                "is_threat_actor": True,
            },
        }
    )

    assert client.get_entity_aliases("entity-2") == []


# Scenario: an API error is swallowed and yields no aliases (issue #7118)
def test_get_entity_aliases_returns_empty_list_on_error():
    client = _build_client()
    client.session.get.side_effect = requests.RequestException("boom")

    assert client.get_entity_aliases("entity-3") == []
    client.helper.connector_logger.warning.assert_called_once()
