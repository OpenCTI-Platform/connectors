"""A domain urlscan.io cannot resolve is not a fatal error (issue #7908)."""

import json
from unittest.mock import MagicMock

import pytest
import requests
from urlscan_enrichment_services import UrlscanConnector
from urlscan_enrichment_services.client import (
    UrlscanClient,
    UrlscanUnresolvableDomainError,
)

DNS_ERROR = {
    "message": "DNS Error - Could not resolve domain",
    "description": "The domain example.invalid could not be resolved.",
    "status": 400,
}


def _response(status: int, body: dict) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.reason = "Bad Request"
    response._content = json.dumps(body).encode()
    return response


def _make_client(response: requests.Response) -> UrlscanClient:
    client = UrlscanClient(MagicMock(), "api-key", "public")
    client.session = MagicMock()
    client.session.post.return_value = response
    return client


def test_submission_raises_unresolvable_domain_on_dns_error():
    client = _make_client(_response(400, DNS_ERROR))

    with pytest.raises(UrlscanUnresolvableDomainError, match="DNS Error"):
        client.urlscan_submission("example.invalid")


def test_submission_keeps_value_error_on_other_400():
    client = _make_client(_response(400, {"message": "Missing URL", "status": 400}))

    with pytest.raises(ValueError):
        client.urlscan_submission("example.com")


def _make_connector() -> UrlscanConnector:
    connector = UrlscanConnector.__new__(UrlscanConnector)
    connector.helper = MagicMock()
    connector.helper.connect_scope = "Domain-Name,Url,Hostname"
    connector.helper.stix2_create_bundle.side_effect = lambda objects: objects
    connector.helper.send_stix2_bundle.return_value = ["bundle"]
    connector.config = MagicMock()
    connector.config.connector.max_tlp = "TLP:AMBER"
    connector.client = MagicMock()
    connector.tlp = None
    return connector


def test_unresolvable_domain_sends_the_entity_back_unchanged():
    connector = _make_connector()
    connector.client.urlscan_submission.side_effect = UrlscanUnresolvableDomainError(
        DNS_ERROR["message"]
    )
    stix_entity = {
        "id": "domain-name--00000000-0000-4000-8000-000000000000",
        "type": "domain-name",
        "value": "example.invalid",
    }
    data = {
        "entity_id": "x",
        "stix_entity": stix_entity,
        "enrichment_entity": {"entity_type": "Domain-Name", "objectMarking": []},
        "stix_objects": [stix_entity],
    }

    result = connector._process_message(data)

    connector.client.urlscan_result.assert_not_called()
    connector.helper.send_stix2_bundle.assert_called_once_with([stix_entity])
    connector.helper.connector_logger.warning.assert_called_once()
    assert "DNS Error" in result
