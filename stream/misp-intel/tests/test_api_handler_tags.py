"""
Regression tests for tag preservation in MispApiHandler.create_event() /
update_event().

convert_bundle_to_event() (stix_to_misp_converter.py) attaches MISP tags
(derived from TLP/PAP object_marking_refs, see #7011) to the "Tag" list of
each attribute in the flat event dict it returns. create_event() and
update_event() used to discard the return value of add_attribute(), so
those tags never made it onto the MISPAttribute objects actually sent to
MISP. This file locks in the fix.

Like the rest of this connector's test suite, no live MISP instance is
required: PyMISP itself is mocked.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def api_handler():
    """Create a MispApiHandler with PyMISP mocked out."""
    with patch("misp_intel_connector.api_handler.PyMISP") as mock_pymisp_cls:
        mock_misp = MagicMock()
        mock_pymisp_cls.return_value = mock_misp

        from misp_intel_connector.api_handler import MispApiHandler

        helper = MagicMock()
        helper.connector_logger = MagicMock()

        config = MagicMock()
        config.misp.url = "https://misp.example.com"
        config.misp.api_key.get_secret_value.return_value = "fake-key"
        config.misp.ssl_verify = True
        config.misp.distribution_level = 1
        config.misp.threat_level = 2
        config.misp.owner_org = None
        config.misp.publish_on_create = False
        config.misp.publish_on_update = False

        handler = MispApiHandler(helper, config)
        handler.misp = mock_misp
        return handler


def test_create_event_preserves_attribute_level_tags(api_handler):
    """
    A top-level Attribute carrying a Tag (e.g. tlp:red from an indicator's
    object_marking_refs, see #7011) must still have that tag on the
    MISPAttribute object actually passed to misp.add_event().
    """
    event_data = {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "info": "Test event",
        "Attribute": [
            {
                "type": "ip-dst",
                "value": "1.2.3.4",
                "category": "Network activity",
                "to_ids": True,
                "comment": "",
                "Tag": [{"name": "tlp:red"}],
            }
        ],
    }

    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": event_data["uuid"], "info": "Test event"}
    }

    api_handler.create_event(event_data)

    # Inspect the MISPEvent object actually passed to misp.add_event()
    submitted_event = api_handler.misp.add_event.call_args[0][0]
    assert len(submitted_event.attributes) == 1
    attr = submitted_event.attributes[0]
    tag_names = [tag.name for tag in attr.tags]
    assert "tlp:red" in tag_names


def test_create_event_preserves_object_attribute_level_tags(api_handler):
    """
    A MISP Object's Attribute carrying a Tag (e.g. PAP:AMBER applied to each
    Attribute of an ip-port object, since pymisp.MISPObject itself does not
    support add_tag() - MISP/PyMISP#168) must survive create_event().
    """
    event_data = {
        "uuid": "22222222-2222-2222-2222-222222222222",
        "info": "Test event with object",
        "Object": [
            {
                "name": "ip-port",
                "comment": "",
                "Attribute": [
                    {
                        "object_relation": "ip",
                        "value": "5.6.7.8",
                        "type": "ip-dst",
                        "to_ids": False,
                        "comment": "",
                        "Tag": [{"name": "PAP:AMBER"}],
                    }
                ],
            }
        ],
    }

    api_handler.misp.add_event.return_value = {
        "Event": {"id": "2", "uuid": event_data["uuid"], "info": "Test event with object"}
    }

    api_handler.create_event(event_data)

    submitted_event = api_handler.misp.add_event.call_args[0][0]
    assert len(submitted_event.objects) == 1
    obj = submitted_event.objects[0]
    assert len(obj.attributes) == 1
    obj_attr = obj.attributes[0]
    tag_names = [tag.name for tag in obj_attr.tags]
    assert "PAP:AMBER" in tag_names


def test_update_event_preserves_attribute_level_tags(api_handler):
    """Same tag-preservation guarantee, but through the update_event() path."""
    existing_event = MagicMock()
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    existing_event.tags = []

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "3",
            "uuid": "33333333-3333-3333-3333-333333333333",
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        "Attribute": [
            {
                "type": "domain",
                "value": "evil.example.com",
                "category": "Network activity",
                "to_ids": True,
                "comment": "",
                "Tag": [{"name": "tlp:amber"}],
            }
        ],
    }

    api_handler.update_event("33333333-3333-3333-3333-333333333333", event_data)

    # existing_event is a MagicMock, so add_attribute() returns a MagicMock too;
    # verify add_tag() was called on it with the expected tag name.
    added_attr = existing_event.add_attribute.return_value
    added_attr.add_tag.assert_called_once_with("tlp:amber")


def test_create_event_attribute_without_tags_does_not_error(api_handler):
    """Attributes with no Tag key at all must not raise and must add no tags."""
    event_data = {
        "uuid": "44444444-4444-4444-4444-444444444444",
        "info": "No tags event",
        "Attribute": [
            {
                "type": "url",
                "value": "http://example.com",
                "category": "Network activity",
                "to_ids": False,
                "comment": "",
            }
        ],
    }

    api_handler.misp.add_event.return_value = {
        "Event": {"id": "4", "uuid": event_data["uuid"], "info": "No tags event"}
    }

    api_handler.create_event(event_data)

    submitted_event = api_handler.misp.add_event.call_args[0][0]
    attr = submitted_event.attributes[0]
    assert list(attr.tags) == []
