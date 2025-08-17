import json
import uuid
from typing import Any

import pytest
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture
from shodan_internetdb.config import ConfigConnector
from shodan_internetdb.connector import ShodanInternetDBConnector


@pytest.fixture(name="data")
def fixture_data() -> dict[str, Any]:
    ipv4_addr_uuid = uuid.uuid4()
    marking_definition_uuid = uuid.uuid4()
    return {
        "enrichment_entity": {
            "entity_type": "ipv4-addr",
            "objectMarking": [
                {"definition": "TLP:WHITE", "definition_type": "TLP"},
            ],
        },
        "stix_entity": {
            "id": f"ipv4-addr--{ipv4_addr_uuid}",
            "value": "0.0.0.0",
            "type": "ipv4-addr",
        },
        "stix_objects": [
            {
                "id": f"marking-definition--{marking_definition_uuid}",
                "spec_version": "2.1",
                "type": "marking-definition",
                "definition": {"tlp": "white"},
                "definition_type": "tlp",
                "name": "TLP:WHITE",
            },
            {
                "id": f"ipv4-addr--{ipv4_addr_uuid}",
                "spec_version": "2.1",
                "type": "ipv4-addr",
                "object_marking_refs": [
                    f"marking-definition--{marking_definition_uuid}"
                ],
                "value": "123.122.12.12",
            },
        ],
        "event_type": "INTERNAL_ENRICHMENT",
    }


@pytest.mark.usefixtures("mocked_requests")
def test_connector(helper: OpenCTIConnectorHelper, data: dict[str, Any]) -> None:
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    result = connector.process_message(data=data)
    assert result == "Sending 5 stix bundle(s) for worker import"


@pytest.mark.usefixtures("mocked_requests")
def test_send_bundle(
    mocker: MockerFixture, helper: OpenCTIConnectorHelper, data: dict[str, Any]
) -> None:
    mocked_method = mocker.patch(
        "shodan_internetdb.connector.ShodanInternetDBConnector._send_bundle"
    )
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    connector.process_message(data=data)

    stix_objects_bundle = helper.stix2_create_bundle(*mocked_method.call_args.args)
    bundles_sent = helper.send_stix2_bundle(stix_objects_bundle)

    stix_objects = [json.loads(bundle)["objects"][0] for bundle in bundles_sent]
    assert stix_objects[0]["id"] == data["stix_objects"][0]["id"]
    assert stix_objects[3]["id"] == data["stix_objects"][1]["id"]

    assert stix_objects[0]["type"] == "marking-definition"
    assert stix_objects[1]["type"] == "identity"
    assert stix_objects[2]["type"] == "marking-definition"
    assert stix_objects[3]["type"] == "ipv4-addr"
    assert stix_objects[4]["type"] == "note"


@pytest.mark.usefixtures("mocked_requests")
def test_send_stix2_bundle_update_argument(
    mocker: MockerFixture, helper: OpenCTIConnectorHelper, data: dict[str, Any]
) -> None:
    mocked_method = mocker.patch("pycti.OpenCTIConnectorHelper.send_stix2_bundle")
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    connector.process_message(data=data)
    assert not mocked_method.call_args.kwargs.get("update", False)


@pytest.mark.usefixtures("mocked_requests")
def test_wrong_ip_v4(helper: OpenCTIConnectorHelper, data: dict[str, Any]) -> None:
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    data["stix_entity"]["value"] = "wrong ipv4"
    assert (
        connector.process_message(data=data)
        == "[CONNECTOR] Observable value is not an IPv4 address"
    )


@pytest.mark.usefixtures("mocked_requests")
def test_wrong_scope(helper: OpenCTIConnectorHelper, data: dict[str, Any]) -> None:
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    data["enrichment_entity"]["entity_type"] = "IPv6-Addr"
    assert (
        connector.process_message(data=data)
        == "[CONNECTOR] Failed to process observable, IPv6-Addr is not a supported entity type"
    )


def test_api_error(
    mocker: MockerFixture, helper: OpenCTIConnectorHelper, data: dict[str, Any]
) -> None:
    mocker.patch("shodan_internetdb.client.requests.Session.get", None)
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    assert (
        connector.process_message(data=data)
        == "[CONNECTOR] Skipping observable (Shodan API error)"
    )


def test_api_error_404(
    mocker: MockerFixture, helper: OpenCTIConnectorHelper, data: dict[str, Any]
) -> None:
    mocked_get = mocker.patch("shodan_internetdb.client.requests.Session.get")
    mocked_get.return_value.status_code = 404
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    assert (
        connector.process_message(data=data)
        == "[CONNECTOR] No information available, skipping observable (Shodan 404)"
    )


@pytest.mark.usefixtures("mocked_requests")
def test_wrong_marking(helper: OpenCTIConnectorHelper, data: dict[str, Any]) -> None:
    connector = ShodanInternetDBConnector(config=ConfigConnector(), helper=helper)
    data["enrichment_entity"]["objectMarking"][0]["definition"] = "TLP:RED"
    assert (
        connector.process_message(data=data)
        == "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
        "the connector does not has access to this observable, please check the group of the connector user"
    )
