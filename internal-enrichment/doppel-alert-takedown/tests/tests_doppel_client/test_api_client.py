from unittest.mock import MagicMock

import pytest
import requests
from doppel_client import DoppelClient, DoppelClientError


@pytest.fixture
def client():
    helper = MagicMock()
    doppel_client = DoppelClient(
        helper=helper,
        base_url="https://api.doppel.test",
        api_key="api-key",
        user_api_key="user-api-key",
        organization_code="ACM",
    )
    doppel_client.session = MagicMock()
    response = MagicMock()
    response.content = b'{"id":"ACM-1234"}'
    response.json.return_value = {"id": "ACM-1234"}
    doppel_client.session.get.return_value = response
    doppel_client.session.put.return_value = response
    return doppel_client


def test_client_configures_optional_organization_header():
    with_organization = DoppelClient(
        helper=MagicMock(),
        base_url="https://api.doppel.test",
        api_key="api-key",
        user_api_key="user-api-key",
        organization_code="ACM",
    )
    without_organization = DoppelClient(
        helper=MagicMock(),
        base_url="https://api.doppel.test",
        api_key="api-key",
        user_api_key="user-api-key",
    )

    assert with_organization.session.headers["x-organization-code"] == "ACM"
    assert "x-organization-code" not in without_organization.session.headers


def test_get_alert_reads_current_state_by_id(client):
    result = client.get_alert(alert_id="ACM-1234")

    assert result == {"id": "ACM-1234"}
    client.session.get.assert_called_once_with(
        "https://api.doppel.test/v1/alert",
        params={"id": "ACM-1234"},
        timeout=30,
    )


def test_get_alert_rejects_mismatched_response(client):
    client.session.get.return_value.json.return_value = {"id": "ACM-9999"}

    with pytest.raises(DoppelClientError, match="wrong alert"):
        client.get_alert(alert_id="ACM-1234")


def test_update_alert_supports_the_public_update_surface(client):
    files = [{"file_name": "evidence.png"}]

    result = client.update_alert(
        alert_id="ACM-1234",
        queue_state="monitoring",
        entity_state="active",
        comment="Reviewed in OpenCTI.",
        tag_action="add",
        tag_name="Credential Theft",
        file_action="delete",
        files=files,
    )

    assert result == {"id": "ACM-1234"}
    client.session.put.assert_called_once_with(
        "https://api.doppel.test/v1/alert",
        params={"id": "ACM-1234"},
        json={
            "queue_state": "monitoring",
            "entity_state": "active",
            "comment": "Reviewed in OpenCTI.",
            "tag_action": "add",
            "tag_name": "Credential Theft",
            "file_action": "delete",
            "files": files,
        },
        timeout=30,
    )


def test_request_takedown_can_fall_back_to_entity(client):
    client.request_takedown(
        entity="https://phishing.example",
        comment="Confirmed by OpenCTI.",
    )

    client.session.put.assert_called_once_with(
        "https://api.doppel.test/v1/alert",
        params={"entity": "https://phishing.example"},
        json={
            "queue_state": "actioned",
            "comment": "Confirmed by OpenCTI.",
        },
        timeout=30,
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({}, "Exactly one"),
        (
            {
                "alert_id": "ACM-1234",
                "entity": "https://phishing.example",
                "comment": "test",
            },
            "Exactly one",
        ),
        ({"alert_id": "ACM-1234"}, "At least one"),
        (
            {"alert_id": "ACM-1234", "tag_action": "add"},
            "tag_action and tag_name",
        ),
        (
            {"alert_id": "ACM-1234", "file_action": "upload"},
            "file_action and files",
        ),
        (
            {"alert_id": "not-an-alert-id", "comment": "test"},
            "Invalid Doppel alert ID",
        ),
        (
            {"alert_id": "LONG-1234", "comment": "test"},
            "Invalid Doppel alert ID",
        ),
        (
            {"alert_id": "ACM-1234", "queue_state": "unsupported"},
            "Invalid queue_state",
        ),
        (
            {"alert_id": "ACM-1234", "entity_state": "unsupported"},
            "Invalid entity_state",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "tag_action": "replace",
                "tag_name": "test",
            },
            "Invalid tag_action",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "file_action": "upload",
                "files": [{"file_name": "evidence.png"}],
            },
            "file_to_upload",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "file_action": "delete",
                "files": [
                    {"file_name": f"evidence-{index}.png"} for index in range(11)
                ],
            },
            "between 1 and 10",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "file_action": "delete",
                "files": [
                    {"file_name": "evidence.png"},
                    {"file_name": "evidence.png"},
                ],
            },
            "Duplicate file names",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "file_action": "delete",
                "files": [None],
            },
            "Each file must be an object",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "file_action": "delete",
                "files": [{}, {}],
            },
            "non-empty file_name",
        ),
        (
            {
                "alert_id": "ACM-1234",
                "file_action": "delete",
                "files": [{"file_name": "../evidence.png"}],
            },
            "Invalid file_name",
        ),
        (
            {"alert_id": "ACM-1234", "comment": " "},
            "comment must not be blank",
        ),
    ],
)
def test_update_alert_rejects_malformed_requests(client, kwargs, message):
    with pytest.raises(ValueError, match=message):
        client.update_alert(**kwargs)

    client.session.put.assert_not_called()


def test_update_alert_wraps_request_failures(client):
    client.session.put.return_value.raise_for_status.side_effect = requests.HTTPError(
        "service unavailable"
    )

    with pytest.raises(DoppelClientError, match="ACM-1234"):
        client.request_takedown(
            alert_id="ACM-1234",
            comment="Confirmed by OpenCTI.",
        )
