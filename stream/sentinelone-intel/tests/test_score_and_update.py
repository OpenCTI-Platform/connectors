"""Regression tests for issue #7762.

* SentinelOne uses the STIX ``confidence`` field as the IOC risk score, so
  the OpenCTI score, which the live stream only carries in the OpenCTI
  extension, must be sent in ``confidence``.
* An indicator update must be pushed again, so that a score change reaches
  SentinelOne.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from sentinelone_connector.connector import SentinelOneIntelConnector
from sentinelone_services.client import SentinelOneClient

INDICATOR_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


def make_indicator(score=None, confidence=10, pattern_type="stix"):
    opencti_id = "indicator--11111111-1111-4111-8111-111111111111"
    extension = {"id": opencti_id}
    if score is not None:
        extension["score"] = score
    return {
        "id": opencti_id,
        "type": "indicator",
        "name": "198.51.100.42",
        "pattern_type": pattern_type,
        "pattern": "[ipv4-addr:value = '198.51.100.42']",
        "confidence": confidence,
        "extensions": {INDICATOR_EXTENSION: extension},
    }


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    return helper


@pytest.fixture
def client(helper):
    config = MagicMock()
    config.sentinelone_intel.account_id = "account"
    config.sentinelone_intel.group_id = None
    config.sentinelone_intel.site_id = None
    return SentinelOneClient(config, helper)


def test_payload_sends_score_as_confidence(client):
    indicator = make_indicator(score=85, confidence=10)

    payload = client._generate_indicator_payload(indicator)

    sent = payload["bundle"]["objects"][0]
    assert sent["confidence"] == 85
    assert sent["pattern"] == indicator["pattern"]
    assert sent["extensions"] == indicator["extensions"]


def test_payload_keeps_confidence_without_score(client):
    indicator = make_indicator(score=None, confidence=10)

    payload = client._generate_indicator_payload(indicator)

    assert payload["bundle"]["objects"][0]["confidence"] == 10


def test_payload_sends_zero_score(client):
    indicator = make_indicator(score=0, confidence=10)

    payload = client._generate_indicator_payload(indicator)

    assert payload["bundle"]["objects"][0]["confidence"] == 0


def test_payload_keeps_scope_filter(client):
    payload = client._generate_indicator_payload(make_indicator(score=85))

    assert payload["filter"] == {"tenant": "false", "accountIds": ["account"]}


def _connector(helper):
    connector = SentinelOneIntelConnector.__new__(SentinelOneIntelConnector)
    connector.helper = helper
    connector.client = MagicMock()
    return connector


def _message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


@pytest.mark.parametrize("event", ["create", "update"])
def test_create_and_update_events_push_the_indicator(helper, event):
    connector = _connector(helper)
    indicator = make_indicator(score=85)

    connector.process_message(_message(event, indicator))

    connector.client.create_indicator.assert_called_once_with(indicator)


def test_delete_event_is_ignored(helper):
    connector = _connector(helper)

    connector.process_message(_message("delete", make_indicator(score=85)))

    connector.client.create_indicator.assert_not_called()


def test_non_stix_indicator_is_ignored(helper):
    connector = _connector(helper)

    connector.process_message(
        _message("update", make_indicator(score=85, pattern_type="sigma"))
    )

    connector.client.create_indicator.assert_not_called()
