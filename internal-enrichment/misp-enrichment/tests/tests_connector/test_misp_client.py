from unittest.mock import MagicMock

import pytest
from connector.misp_client import MispClient
from connectors_sdk.exceptions.error import DataRetrievalError


@pytest.fixture
def pymisp(monkeypatch) -> MagicMock:
    instance = MagicMock()
    monkeypatch.setattr(
        "connector.misp_client.PyMISP", MagicMock(return_value=instance)
    )
    return instance


def _attribute(attribute_id: str, event_id: str, value: str) -> dict:
    return {"id": attribute_id, "event_id": event_id, "value": value}


def test_search_groups_attributes_by_event(pymisp):
    pymisp.search.side_effect = [
        {"Attribute": [_attribute("1", "10", "abc"), _attribute("2", "20", "abc")]},
        {"Attribute": [_attribute("3", "10", "def"), _attribute("1", "10", "abc")]},
    ]
    pymisp.get_event.side_effect = lambda event_id, pythonify: {
        "Event": {"id": event_id, "info": f"Event {event_id}"}
    }

    matches = MispClient("https://misp", "key").search(["abc", "def"])

    assert pymisp.search.call_count == 2
    pymisp.search.assert_any_call(controller="attributes", value="abc", pythonify=False)
    assert [match.event_id for match in matches] == ["10", "20"]
    assert [a["id"] for a in matches[0].attributes] == ["1", "3"]
    assert [a["id"] for a in matches[1].attributes] == ["2"]
    assert pymisp.get_event.call_count == 2


def test_search_without_attribute_does_not_fetch_events(pymisp):
    pymisp.search.return_value = {"Attribute": []}

    assert MispClient("https://misp", "key").search(["abc"]) == []
    pymisp.get_event.assert_not_called()


@pytest.mark.parametrize(
    "search_result",
    [
        pytest.param(Exception("connection refused"), id="exception"),
        pytest.param({"errors": (403, "Forbidden")}, id="error_response"),
        pytest.param([], id="unexpected_response"),
    ],
)
def test_search_raises_when_attribute_search_fails(pymisp, search_result):
    if isinstance(search_result, Exception):
        pymisp.search.side_effect = search_result
    else:
        pymisp.search.return_value = search_result

    with pytest.raises(DataRetrievalError):
        MispClient("https://misp", "key").search(["abc"])


@pytest.mark.parametrize(
    "get_event_result",
    [
        pytest.param(Exception("timeout"), id="exception"),
        pytest.param({"errors": (404, "Invalid event")}, id="error_response"),
    ],
)
def test_search_raises_when_event_retrieval_fails(pymisp, get_event_result):
    pymisp.search.return_value = {"Attribute": [_attribute("1", "10", "abc")]}
    if isinstance(get_event_result, Exception):
        pymisp.get_event.side_effect = get_event_result
    else:
        pymisp.get_event.return_value = get_event_result

    with pytest.raises(DataRetrievalError):
        MispClient("https://misp", "key").search(["abc"])
