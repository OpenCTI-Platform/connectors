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
        # get_marking_types_allowlist() is exercised by
        # stix_to_misp_converter.py (not this test module) to decide which
        # markings are converted to tags at all. It is set here purely for
        # fixture realism; _connector_managed_tag_prefixes() itself no
        # longer consults it - the set of prefixes update_event() may
        # reconcile/remove is fixed (tlp:/pap:/report-type:), see
        # _CONNECTOR_MANAGED_TAG_PREFIXES in api_handler.py and the
        # "Generic allow-listed tags become stale during event updates" /
        # "Updates delete manually added tags in allow-listed namespaces"
        # Copilot review findings on PR #7764.
        config.misp.get_marking_types_allowlist.return_value = {
            "TLP",
            "PAP",
            "CLASSIFICATION",
        }

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
        "Event": {
            "id": "2",
            "uuid": event_data["uuid"],
            "info": "Test event with object",
        }
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


def test_create_event_does_not_crash_on_event_level_tag_dicts(api_handler):
    """
    Regression test for a Copilot review finding on PR #7764 ("Normalize
    event tag dictionaries before adding them"): event_data["Tag"]
    (event-level tags, e.g. TLP/PAP/report_types tags produced by
    convert_bundle_to_event()) is a list of flat dicts such as
    {"name": "tlp:red"}, NOT a list of MISPTag objects or bare strings.

    create_event() used to forward these dicts directly to
    misp_event.add_tag(tag), instead of normalizing them with _tag_names()
    the way update_event() already did. This locks in the fix so both
    creation and update paths behave identically: the resulting MISPEvent
    carries proper tag(s) named after the dict's "name" key.
    """
    event_data = {
        "uuid": "66666666-6666-6666-6666-666666666666",
        "info": "Event with event-level tags",
        # Flat dicts, as produced by AbstractMISP.to_dict() /
        # convert_bundle_to_event() - not MISPTag objects.
        "Tag": [
            {"name": "tlp:red"},
            {"name": "report-type:threat-report"},
        ],
    }

    api_handler.misp.add_event.return_value = {
        "Event": {
            "id": "6",
            "uuid": event_data["uuid"],
            "info": "Event with event-level tags",
        }
    }

    # Must not raise.
    api_handler.create_event(event_data)

    submitted_event = api_handler.misp.add_event.call_args[0][0]
    tag_names = [tag.name for tag in submitted_event.tags]
    assert "tlp:red" in tag_names
    assert "report-type:threat-report" in tag_names


def test_update_event_does_not_crash_on_event_level_tag_dicts(api_handler):
    """
    Regression test for a Copilot review finding on PR #7764: event_data["Tag"]
    (event-level tags, e.g. TLP/PAP/report_types tags produced by
    convert_bundle_to_event()) is a list of flat dicts such as
    {"name": "tlp:red"}, NOT a list of MISPTag objects.

    Before the fix, update_event() did `tag.name` directly on these dicts,
    which raises AttributeError - meaning update_event() would crash on
    every event that actually carries a marking/report_type tag, which is
    the very feature this connector adds. This must no longer raise, and
    must add only the genuinely new (not-already-present) tag names.
    """
    existing_tag_red = MagicMock()
    existing_tag_red.name = "tlp:red"

    existing_event = MagicMock()
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    # Existing event already has tlp:red as a real MISPTag-like object
    existing_event.tags = [existing_tag_red]

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "5",
            "uuid": "55555555-5555-5555-5555-555555555555",
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        # Flat dicts, as produced by AbstractMISP.to_dict() /
        # convert_bundle_to_event() - not MISPTag objects.
        "Tag": [
            {"name": "tlp:red"},  # already present -> must be skipped
            {"name": "report-type:threat-report"},  # new -> must be added
        ],
    }

    # Must not raise AttributeError.
    api_handler.update_event("55555555-5555-5555-5555-555555555555", event_data)

    added_tag_names = [call.args[0] for call in existing_event.add_tag.call_args_list]
    assert "report-type:threat-report" in added_tag_names
    assert "tlp:red" not in added_tag_names


def test_update_event_removes_stale_connector_managed_tag(api_handler):
    """
    Regression test for a Copilot review finding on PR #7764 ("Reconcile
    stale event marking and report-type tags during updates"): if a
    container's marking changes (e.g. TLP RED -> GREEN), update_event() must
    remove the now-stale "tlp:red" tag from the MISP event (via
    self.misp.untag()) instead of just adding "tlp:green" alongside it.
    """
    existing_tag_red = MagicMock()
    existing_tag_red.name = "tlp:red"

    existing_event = MagicMock()
    existing_event.uuid = "77777777-7777-7777-7777-777777777777"
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    existing_event.tags = [existing_tag_red]

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "7",
            "uuid": existing_event.uuid,
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        # Marking changed from TLP:RED to TLP:GREEN.
        "Tag": [{"name": "tlp:green"}],
    }

    api_handler.update_event(existing_event.uuid, event_data)

    # The stale tlp:red tag must have been actively removed from MISP...
    api_handler.misp.untag.assert_called_once_with(existing_event.uuid, "tlp:red")
    # ...and removed from the local tags list...
    assert existing_tag_red not in existing_event.tags
    # ...while the new tlp:green tag must have been added.
    added_tag_names = [call.args[0] for call in existing_event.add_tag.call_args_list]
    assert "tlp:green" in added_tag_names


def test_update_event_does_not_remove_non_connector_managed_tags(api_handler):
    """
    A tag that does not match a connector-managed prefix (tlp:/pap:/
    report-type:, see _connector_managed_tag_prefixes()) - e.g. one added
    manually by a MISP analyst, or a generic OpenCTI label tag - must never
    be removed by update_event()'s stale-tag reconciliation, even if it is
    absent from the new payload's Tag list.
    """
    existing_tag_manual = MagicMock()
    existing_tag_manual.name = "analyst:reviewed"

    existing_tag_red = MagicMock()
    existing_tag_red.name = "tlp:red"

    existing_event = MagicMock()
    existing_event.uuid = "88888888-8888-8888-8888-888888888888"
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    existing_event.tags = [existing_tag_manual, existing_tag_red]

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "8",
            "uuid": existing_event.uuid,
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        # New payload no longer carries tlp:red, and never carried the
        # manually-added "analyst:reviewed" tag in the first place.
        "Tag": [{"name": "tlp:green"}],
    }

    api_handler.update_event(existing_event.uuid, event_data)

    # Only the connector-managed stale tag (tlp:red) is untagged - the
    # manually-added, non-connector-managed tag is left alone.
    api_handler.misp.untag.assert_called_once_with(existing_event.uuid, "tlp:red")
    assert existing_tag_manual in existing_event.tags


def test_update_event_does_not_remove_stale_tags_for_other_allow_listed_marking_types(
    api_handler,
):
    """
    Regression test for the Copilot review findings on PR #7764 "Generic
    allow-listed tags become stale during event updates" and "Updates
    delete manually added tags in allow-listed namespaces".

    Even when a deployer adds a non-TLP/PAP marking type (e.g.
    "CLASSIFICATION") to MISP_MARKING_TYPES_TO_CONVERT so it gets converted
    to a tag on event *creation*, update_event()'s stale-tag reconciliation
    must NOT auto-remove such a tag when it is missing from a later
    payload: STIXtoMISPConverter._get_marking_tag() does not guarantee that
    tag carries a predictable "classification:" prefix, so treating it as
    connector-managed could either silently fail to clean it up or, worse,
    delete an unrelated manually-added tag that happens to share a
    namespace. Only the fixed tlp:/pap:/report-type: prefixes are
    reconciled - see _CONNECTOR_MANAGED_TAG_PREFIXES in api_handler.py.
    """
    existing_tag_classification = MagicMock()
    existing_tag_classification.name = "classification:secret"

    existing_event = MagicMock()
    existing_event.uuid = "99999999-9999-9999-9999-999999999999"
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    existing_event.tags = [existing_tag_classification]

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "9",
            "uuid": existing_event.uuid,
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        # The new payload no longer carries the "classification:secret" tag.
        "Tag": [],
    }

    api_handler.update_event(existing_event.uuid, event_data)

    # A non-tlp/pap/report-type tag is never auto-removed, regardless of
    # whether its marking type is allow-listed for conversion.
    api_handler.misp.untag.assert_not_called()
    assert existing_tag_classification in existing_event.tags
