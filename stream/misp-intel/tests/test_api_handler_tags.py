"""
Tests for event-level tag handling in MispApiHandler.

The event data passed to create_event()/update_event() is the real output of
STIXtoMISPConverter.convert_bundle_to_event(), so tags have exactly the same
shape as in production.
"""

from unittest.mock import MagicMock, patch

import pytest
from misp_intel_connector.api_handler import MispApiHandler, _tag_names
from misp_intel_connector.stix_to_misp_converter import STIXtoMISPConverter
from pymisp import MISPEvent, MISPTag

EVENT_UUID = "33333333-3333-3333-3333-333333333333"
TLP_RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"


@pytest.fixture
def config():
    config = MagicMock()
    config.misp.url = "https://misp.example.com"
    config.misp.api_key.get_secret_value.return_value = "fake-key"
    config.misp.ssl_verify = True
    config.misp.distribution_level = 1
    config.misp.threat_level = 2
    config.misp.owner_org = None
    config.misp.publish_on_create = False
    config.misp.publish_on_update = False
    config.misp.get_marking_types_allowlist.return_value = {"TLP", "PAP"}
    return config


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return helper


@pytest.fixture
def api_handler(helper, config):
    with patch("misp_intel_connector.api_handler.PyMISP") as mock_pymisp_cls:
        mock_pymisp_cls.return_value = MagicMock()
        handler = MispApiHandler(helper, config)
    return handler


def _event_data(helper, config):
    bundle = {
        "type": "bundle",
        "id": "bundle--66666666-6666-6666-6666-666666666666",
        "objects": [
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": TLP_RED_ID,
                "definition_type": "TLP",
                "name": "TLP:RED",
            },
            {
                "type": "report",
                "spec_version": "2.1",
                "id": f"report--{EVENT_UUID}",
                "name": "Test report",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "published": "2026-01-01T00:00:00.000Z",
                "object_marking_refs": [TLP_RED_ID],
                "report_types": ["threat-report"],
                "object_refs": [],
            },
        ],
    }
    converter = STIXtoMISPConverter(helper, config)
    return converter.convert_bundle_to_event(bundle, custom_uuid=EVENT_UUID)


def test_tag_names_accepts_misp_tags_dicts_and_strings():
    tag = MISPTag()
    tag.from_dict(name="tlp:red")

    names = _tag_names([tag, {"name": "PAP:AMBER"}, "source:opencti", None])

    assert names == ["tlp:red", "PAP:AMBER", "source:opencti"]


def test_converter_output_contains_event_tags(helper, config):
    event_data = _event_data(helper, config)

    tag_names = _tag_names(event_data["Tag"])

    assert "tlp:red" in tag_names
    assert "report-type:threat-report" in tag_names


def test_create_event_with_converter_output(api_handler, helper, config):
    event_data = _event_data(helper, config)
    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": "Test report"}
    }

    result = api_handler.create_event(event_data)

    assert result["uuid"] == EVENT_UUID
    sent_event = api_handler.misp.add_event.call_args[0][0]
    sent_tags = _tag_names(sent_event.tags)
    assert "tlp:red" in sent_tags
    assert "report-type:threat-report" in sent_tags


def test_update_event_with_converter_output(api_handler, helper, config):
    """Updating an already tagged event must not raise on MISPTag entries."""
    event_data = _event_data(helper, config)
    existing_event = MISPEvent()
    existing_event.uuid = EVENT_UUID
    existing_event.info = "Test report"
    existing_event.add_tag("tlp:red")
    existing_event.add_tag("analyst:manual")
    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": "Test report"}
    }

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    sent_event = api_handler.misp.update_event.call_args[0][0]
    sent_tags = _tag_names(sent_event.tags)
    assert sent_tags.count("tlp:red") == 1
    assert "report-type:threat-report" in sent_tags
    assert "analyst:manual" in sent_tags
