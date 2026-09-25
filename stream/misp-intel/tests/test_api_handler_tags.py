"""
Regression tests for tag preservation in MispApiHandler.create_event() /
update_event().

convert_bundle_to_event() (stix_to_misp_converter.py) attaches MISP tags
(derived from TLP/PAP object_marking_refs, see #7011) to the "Tag" list of
each attribute in the flat event dict it returns. create_event() and
update_event() used to discard the return value of add_attribute(), so
those tags never made it onto the MISPAttribute objects actually sent to
MISP. This file locks in the fix.

It also covers the persisted-state-backed reconciliation of stale
event-level tags (tlp:/pap:/report-type:/any other allow-listed marking
type) on update_event(), see api_handler.py's
_get_managed_event_tags()/_set_managed_event_tags()/_clear_managed_event_tags().

Like the rest of this connector's test suite, no live MISP instance is
required: PyMISP itself is mocked. helper.get_state()/set_state() are
backed by a simple in-memory dict to emulate real pycti connector state
persistence.
"""

from unittest.mock import MagicMock, patch

import pytest


def _make_stateful_helper():
    """
    Build a MagicMock helper whose get_state()/set_state() are backed by a
    simple in-memory dict, so tests can assert on what gets persisted (and
    pre-seed state to simulate a prior sync) the same way the real pycti
    OpenCTIConnectorHelper.get_state()/set_state() would round-trip through
    the OpenCTI connector's persisted state.

    :return: (helper mock, state_box) - state_box is a single-item dict
        {"state": ...} so tests can inspect/mutate the "current" state.
    """
    helper = MagicMock()
    helper.connector_logger = MagicMock()

    state_box = {"state": None}

    def _get_state():
        return state_box["state"]

    def _set_state(new_state):
        state_box["state"] = new_state

    helper.get_state.side_effect = _get_state
    helper.set_state.side_effect = _set_state

    return helper, state_box


@pytest.fixture
def stateful_helper():
    """Expose the stateful helper mock and its backing dict to tests."""
    return _make_stateful_helper()


@pytest.fixture
def api_handler(stateful_helper):
    """Create a MispApiHandler with PyMISP mocked out and a stateful helper."""
    with patch("misp_intel_connector.api_handler.PyMISP") as mock_pymisp_cls:
        mock_misp = MagicMock()
        mock_pymisp_cls.return_value = mock_misp

        from misp_intel_connector.api_handler import MispApiHandler

        helper, _state_box = stateful_helper

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
        # fixture realism; the persisted-state-backed stale-tag
        # reconciliation in update_event() no longer consults it at all -
        # it tracks the *actual* tag names the connector previously added
        # per event (see _get_managed_event_tags()/_set_managed_event_tags()
        # in api_handler.py), regardless of which allow-listed marking type
        # produced them. This is what fixes the Copilot review findings
        # "Generic allow-listed tags become stale during event updates" and
        # "Updates delete manually added tags in allow-listed namespaces"
        # on PR #7764.
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
    existing_event.uuid = "33333333-3333-3333-3333-333333333333"
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


def test_create_event_persists_managed_tags_state(api_handler, stateful_helper):
    """
    create_event() must record, in persisted connector state, exactly which
    event-level tags it just added for this event UUID - so a future
    update_event() call can reconcile (remove) precisely those tags once
    they become stale, without guessing from a fixed tag-name prefix.
    """
    _helper, state_box = stateful_helper

    event_data = {
        "uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "info": "Event with event-level tags",
        "Tag": [
            {"name": "tlp:red"},
            {"name": "report-type:threat-report"},
        ],
    }

    api_handler.misp.add_event.return_value = {
        "Event": {
            "id": "10",
            "uuid": event_data["uuid"],
            "info": "Event with event-level tags",
        }
    }

    api_handler.create_event(event_data)

    managed = state_box["state"]["misp_connector_managed_event_tags"]
    assert set(managed[event_data["uuid"]]) == {"tlp:red", "report-type:threat-report"}


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
    existing_event.uuid = "55555555-5555-5555-5555-555555555555"
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


def test_update_event_removes_stale_connector_managed_tag(api_handler, stateful_helper):
    """
    Regression test for a Copilot review finding on PR #7764 ("Reconcile
    stale event marking and report-type tags during updates"): if a
    container's marking changes (e.g. TLP RED -> GREEN), update_event() must
    remove the now-stale "tlp:red" tag from the MISP event (via
    self.misp.untag()) instead of just adding "tlp:green" alongside it.

    "tlp:red" is recognized as removable because it was previously recorded
    in persisted connector state as a tag *this connector* added on a prior
    sync of the same event (simulating create_event() or an earlier
    update_event() having run first) - not because it happens to match a
    fixed prefix.
    """
    _helper, state_box = stateful_helper

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

    # Simulate a prior sync of this event having recorded "tlp:red" as
    # connector-managed.
    state_box["state"] = {
        "misp_connector_managed_event_tags": {existing_event.uuid: ["tlp:red"]}
    }

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
    # ...and the new managed-tag set persisted for the next reconciliation round.
    managed = state_box["state"]["misp_connector_managed_event_tags"]
    assert managed[existing_event.uuid] == ["tlp:green"]


def test_update_event_does_not_remove_manually_added_tag_in_managed_namespace(
    api_handler, stateful_helper
):
    """
    Regression test for the Copilot review finding "Updates delete
    manually added tags in allow-listed namespaces" on PR #7764.

    A tag that a MISP analyst added manually - even one that happens to
    share a tlp:/pap:/report-type: namespace with connector-managed tags,
    e.g. a manually-added "tlp:red" - must never be removed by
    update_event()'s stale-tag reconciliation, because it was never
    recorded in persisted connector state as a tag *this connector* added.
    Only the genuinely connector-added tag ("report-type:threat-report",
    recorded in state below) is eligible for removal.
    """
    _helper, state_box = stateful_helper

    existing_tag_manual_tlp = MagicMock()
    existing_tag_manual_tlp.name = "tlp:red"

    existing_tag_report_type = MagicMock()
    existing_tag_report_type.name = "report-type:threat-report"

    existing_event = MagicMock()
    existing_event.uuid = "88888888-8888-8888-8888-888888888888"
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    existing_event.tags = [existing_tag_manual_tlp, existing_tag_report_type]

    # Only "report-type:threat-report" was ever recorded as connector-added
    # for this event; "tlp:red" was added manually by an analyst and was
    # never recorded in state.
    state_box["state"] = {
        "misp_connector_managed_event_tags": {
            existing_event.uuid: ["report-type:threat-report"]
        }
    }

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
        # New payload no longer carries the report-type tag, and never
        # carried the manually-added "tlp:red" tag in the first place.
        "Tag": [],
    }

    api_handler.update_event(existing_event.uuid, event_data)

    # Only the previously-recorded connector-managed tag is untagged - the
    # manually-added tag sharing the "tlp:" namespace is left alone.
    api_handler.misp.untag.assert_called_once_with(
        existing_event.uuid, "report-type:threat-report"
    )
    assert existing_tag_manual_tlp in existing_event.tags


def test_update_event_reconciles_generic_allow_listed_marking_type_tag(
    api_handler, stateful_helper
):
    """
    Regression test for the Copilot review finding "Generic allow-listed
    tags become stale during event updates" on PR #7764.

    A non-TLP/PAP allow-listed marking type (e.g. "CLASSIFICATION") whose
    resulting tag does not follow a predictable "{definition_type}:"
    prefix is now correctly reconciled (removed once stale), because
    reconciliation is driven by the persisted record of what the connector
    itself previously added for this event - not by guessing from a fixed
    prefix set.
    """
    _helper, state_box = stateful_helper

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

    # This event's "classification:secret" tag was previously added by the
    # connector itself (e.g. via create_event() when CLASSIFICATION was
    # allow-listed in MISP_MARKING_TYPES_TO_CONVERT).
    state_box["state"] = {
        "misp_connector_managed_event_tags": {
            existing_event.uuid: ["classification:secret"]
        }
    }

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

    # The stale, connector-added, non-tlp/pap/report-type tag IS removed,
    # because it was recorded as connector-managed in state.
    api_handler.misp.untag.assert_called_once_with(
        existing_event.uuid, "classification:secret"
    )
    assert existing_tag_classification not in existing_event.tags


def test_update_event_with_no_recorded_state_does_not_remove_anything(
    api_handler, stateful_helper
):
    """
    Transitional edge case: an event synced by a pre-upgrade connector
    version (before this state-tracking feature existed) has no recorded
    entry in persisted state. The first update_event() call after
    upgrading must not remove any existing tag purely because it is absent
    from the new payload - it is strictly safer to under-clean once on
    upgrade than to guess and risk deleting a manually-added tag.
    """
    _helper, state_box = stateful_helper
    assert state_box["state"] is None  # no prior state recorded at all

    existing_tag_red = MagicMock()
    existing_tag_red.name = "tlp:red"

    existing_event = MagicMock()
    existing_event.uuid = "12121212-1212-1212-1212-121212121212"
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
            "id": "12",
            "uuid": existing_event.uuid,
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        "Tag": [{"name": "tlp:green"}],
    }

    api_handler.update_event(existing_event.uuid, event_data)

    # No prior record for this event -> nothing is removed this round, even
    # though "tlp:red" is absent from the new payload.
    api_handler.misp.untag.assert_not_called()
    assert existing_tag_red in existing_event.tags
    # The new tag is still added normally.
    added_tag_names = [call.args[0] for call in existing_event.add_tag.call_args_list]
    assert "tlp:green" in added_tag_names
    # From now on, state records exactly "tlp:green" for future reconciliation.
    managed = state_box["state"]["misp_connector_managed_event_tags"]
    assert managed[existing_event.uuid] == ["tlp:green"]


def test_update_event_retries_failed_tag_removal_next_round(
    api_handler, stateful_helper
):
    """
    Regression test for the Copilot review finding "Retain failed tag
    removals for later retry" on PR #7764.

    If self.misp.untag() raises while removing a stale connector-managed
    tag (e.g. a transient MISP-side/network error), that tag must stay
    recorded as connector-managed in persisted state afterwards, so the
    *next* update_event() call retries removing it - instead of the
    failure being silently dropped forever (which would leave a
    permanently stale tag on the MISP event with no further attempt to
    clean it up).
    """
    _helper, state_box = stateful_helper

    existing_tag_red = MagicMock()
    existing_tag_red.name = "tlp:red"

    existing_event = MagicMock()
    existing_event.uuid = "14141414-1414-1414-1414-141414141414"
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    existing_event.tags = [existing_tag_red]

    # "tlp:red" was previously recorded as connector-managed for this event.
    state_box["state"] = {
        "misp_connector_managed_event_tags": {existing_event.uuid: ["tlp:red"]}
    }

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "14",
            "uuid": existing_event.uuid,
            "info": "Updated info",
        }
    }
    # Simulate a transient failure removing the stale tag from MISP.
    api_handler.misp.untag.side_effect = Exception("MISP is temporarily unavailable")

    event_data = {
        "info": "Updated info",
        # tlp:red is no longer in the new payload - it is now stale.
        "Tag": [],
    }

    # Must not raise despite untag() failing - the failure is logged and
    # handled, not propagated.
    api_handler.update_event(existing_event.uuid, event_data)

    api_handler.misp.untag.assert_called_once_with(existing_event.uuid, "tlp:red")
    # Since removal failed, the tag must remain on the local event object -
    # it was never actually removed from MISP.
    assert existing_tag_red in existing_event.tags
    # It must still be recorded as connector-managed, so the next
    # update_event() call retries removing it.
    managed = state_box["state"]["misp_connector_managed_event_tags"]
    assert managed[existing_event.uuid] == ["tlp:red"]


def test_update_event_does_not_promote_pre_existing_tag_to_managed(
    api_handler, stateful_helper
):
    """
    Regression test for the Copilot review finding "Do not mark
    pre-existing tags as connector-managed" on PR #7764.

    A tag that already existed on the MISP event before this update for
    some other reason (e.g. manually added by an analyst) and merely also
    happens to be present in the new OpenCTI payload (e.g. because the
    analyst independently chose the same TLP value the container carries)
    must NOT be promoted to "connector-managed" in persisted state just
    because it matches. Only tags genuinely newly added by the connector
    this round are recorded as managed - otherwise a later, unrelated
    change to the container's marking would cause this manually-added tag
    to be deleted by stale-tag reconciliation, even though the connector
    never actually added it.
    """
    _helper, state_box = stateful_helper

    existing_tag_manual_tlp = MagicMock()
    existing_tag_manual_tlp.name = "tlp:red"

    existing_event = MagicMock()
    existing_event.uuid = "15151515-1515-1515-1515-151515151515"
    existing_event.info = "Old info"
    existing_event.distribution = 1
    existing_event.threat_level_id = 2
    existing_event.analysis = 2
    existing_event.objects = []
    existing_event.attributes = []
    # "tlp:red" already exists on the event (e.g. added manually) and was
    # never recorded as connector-managed in state.
    existing_event.tags = [existing_tag_manual_tlp]
    state_box["state"] = {
        "misp_connector_managed_event_tags": {
            "other-event-uuid": ["pap:amber"],
        }
    }

    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {
            "id": "15",
            "uuid": existing_event.uuid,
            "info": "Updated info",
        }
    }

    event_data = {
        "info": "Updated info",
        # The new payload happens to also carry "tlp:red" - coincidentally
        # matching the pre-existing manual tag.
        "Tag": [{"name": "tlp:red"}],
    }

    api_handler.update_event(existing_event.uuid, event_data)

    # Nothing is removed (it is not stale) and no new tag needs to be added
    # (it already matches), so untag()/add_tag() are not called for it.
    api_handler.misp.untag.assert_not_called()
    assert existing_tag_manual_tlp in existing_event.tags

    # Crucially, this event must NOT gain a managed-tags record: the
    # pre-existing "tlp:red" was never actually added by the connector,
    # so it must not be treated as connector-managed going forward.
    managed = state_box["state"]["misp_connector_managed_event_tags"]
    assert existing_event.uuid not in managed
    # Unrelated events' records are left untouched.
    assert managed["other-event-uuid"] == ["pap:amber"]
