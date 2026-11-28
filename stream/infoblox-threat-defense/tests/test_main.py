import json
from unittest.mock import MagicMock, patch

import pytest
from main import InfobloxThreatDefenseConnector


@pytest.fixture
def connector():
    instance = InfobloxThreatDefenseConnector.__new__(InfobloxThreatDefenseConnector)
    instance.helper = MagicMock()
    instance.infoblox_api_key = "token"
    instance.infoblox_verify_ssl = True
    instance.infoblox_url = "https://csp.infoblox.com"
    return instance


def _put_items(connector, updated_item, operation):
    get_response = MagicMock(status_code=200)
    get_response.json.return_value = {
        "results": {
            "id": 1,
            "name": "list",
            "type": "custom_list",
            "items_described": [
                {"item": "manual.example", "description": "added by an analyst"},
                {"item": "other.example", "description": "from another tool"},
            ],
        }
    }
    put_response = MagicMock(status_code=201)

    with patch("requests.request", side_effect=[get_response, put_response]) as call:
        connector.update_custom_list(1, updated_item, operation)

    payload = json.loads(call.call_args_list[1].kwargs["data"])
    return {i["item"]: i["description"] for i in payload["items_described"]}


def test_add_keeps_existing_item_descriptions(connector):
    assert _put_items(connector, "new.example", "add") == {
        "manual.example": "added by an analyst",
        "other.example": "from another tool",
        "new.example": "",
    }


def test_remove_keeps_remaining_item_descriptions(connector):
    assert _put_items(connector, "other.example", "remove") == {
        "manual.example": "added by an analyst",
    }
