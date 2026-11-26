"""
Tests for the export of the container description as a MISP event report.

The converter turns the container description into an EventReport (stable
UUID, named after the container) and MispApiHandler pushes it with the
dedicated event report endpoints, because create_event/update_event rebuild the
event from the converter dict and only copy its Tag, Attribute and Object
entries. The endpoints also make the sync idempotent by UUID.
"""

import logging
from unittest.mock import MagicMock, call, patch

import pytest
from misp_intel_connector.api_handler import LEGACY_DESCRIPTION_COMMENT, MispApiHandler
from misp_intel_connector.stix_to_misp_converter import (
    STIXtoMISPConverter,
    description_report_uuid,
)
from pymisp import MISPAttribute, MISPEvent, MISPEventReport

EVENT_UUID = "33333333-3333-3333-3333-333333333333"
OTHER_EVENT_UUID = "44444444-4444-4444-4444-444444444444"
DESCRIPTION = "# Summary\n\nA **markdown** description."
REPORT_NAME = "Test container"


@pytest.fixture
def config():
    config = MagicMock()
    config.misp.url = "https://misp.example.com"
    config.misp.api_key.get_secret_value.return_value = "fake-key"
    config.misp.ssl_verify = True
    config.misp.distribution_level = 2
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


def _bundle(container_type="report", event_uuid=EVENT_UUID, **container_fields):
    container = {
        "type": container_type,
        "spec_version": "2.1",
        "id": f"{container_type}--{event_uuid}",
        "name": REPORT_NAME,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "object_refs": [],
    }
    container.update(container_fields)
    return {
        "type": "bundle",
        "id": "bundle--66666666-6666-6666-6666-666666666666",
        "objects": [container],
    }


def _convert(helper, config, bundle, custom_uuid=EVENT_UUID):
    converter = STIXtoMISPConverter(helper, config)
    return converter.convert_bundle_to_event(bundle, custom_uuid=custom_uuid)


def _event_data_with_description(helper, config, description=DESCRIPTION):
    return _convert(helper, config, _bundle(description=description))


def _field(report, name):
    return report[name] if isinstance(report, dict) else getattr(report, name)


def _existing_event(reports=(), attributes=()):
    event = MISPEvent()
    event.uuid = EVENT_UUID
    event.info = REPORT_NAME
    event.distribution = 1
    event.threat_level_id = 2
    event.analysis = 2
    for report in reports:
        event.EventReport.append(report)
    for attribute in attributes:
        event.Attribute.append(attribute)
    return event


def _existing_attribute(comment, uuid, value=DESCRIPTION, attribute_type="comment"):
    attribute = MISPAttribute()
    attribute.from_dict(
        type=attribute_type,
        category="Other",
        value=value,
        comment=comment,
        uuid=uuid,
    )
    return attribute


def _existing_report(content=DESCRIPTION, name=REPORT_NAME, distribution=2, **kwargs):
    # distribution defaults to the one set by the config fixture, event_id to
    # the id of the event returned by _prepare_update
    kwargs.setdefault("event_id", "1")
    report = MISPEventReport()
    report.from_dict(
        id=7,
        name=name,
        content=content,
        uuid=description_report_uuid(EVENT_UUID),
        distribution=distribution,
        **kwargs,
    )
    return report


# --- Converter ---------------------------------------------------------------


@pytest.mark.parametrize(
    "container_type", ["report", "grouping", "x-opencti-case-incident"]
)
def test_description_is_exported_as_event_report(helper, config, container_type):
    bundle = _bundle(container_type=container_type, description=DESCRIPTION)

    event_data = _convert(helper, config, bundle)

    reports = event_data["EventReport"]
    assert len(reports) == 1
    report = reports[0]
    assert _field(report, "name") == REPORT_NAME
    assert _field(report, "content") == DESCRIPTION
    assert _field(report, "uuid") == description_report_uuid(EVENT_UUID)
    assert _field(report, "distribution") == 2


def test_description_is_no_longer_a_comment_attribute(helper, config):
    event_data = _event_data_with_description(helper, config)

    attributes = event_data.get("Attribute") or []
    assert not [a for a in attributes if _field(a, "comment") == "Event description"]
    assert not [a for a in attributes if _field(a, "value") == DESCRIPTION]


@pytest.mark.parametrize(
    "description",
    [None, "", "   \n\t "],
    ids=["missing", "empty", "whitespace"],
)
def test_missing_or_blank_description_creates_no_report(helper, config, description):
    fields = {} if description is None else {"description": description}

    event_data = _convert(helper, config, _bundle(**fields))

    assert not event_data.get("EventReport")
    assert not (event_data.get("Attribute") or [])


def test_report_name_and_content_are_stripped(helper, config):
    bundle = _bundle(name="  Test container \n", description=DESCRIPTION + "\n")

    event_data = _convert(helper, config, bundle)

    report = event_data["EventReport"][0]
    assert _field(report, "content") == DESCRIPTION
    assert _field(report, "name") == "Test container"


def test_report_name_is_truncated_to_255_characters(helper, config):
    long_name = "A" * 300
    bundle = _bundle(name=long_name, description=DESCRIPTION)

    event_data = _convert(helper, config, bundle)

    report = event_data["EventReport"][0]
    assert len(_field(report, "name")) == 255
    assert _field(report, "name") == long_name[:255]
    assert event_data["info"] == long_name


def test_report_uuid_is_stable_across_conversions(helper, config):
    first = _event_data_with_description(helper, config)
    second = _event_data_with_description(helper, config)

    assert _field(first["EventReport"][0], "uuid") == _field(
        second["EventReport"][0], "uuid"
    )
    assert _field(first["EventReport"][0], "uuid") == description_report_uuid(
        EVENT_UUID
    )


def test_report_uuid_differs_between_containers(helper, config):
    first = _event_data_with_description(helper, config)
    other = _convert(
        helper,
        config,
        _bundle(event_uuid=OTHER_EVENT_UUID, description=DESCRIPTION),
        custom_uuid=OTHER_EVENT_UUID,
    )

    assert _field(first["EventReport"][0], "uuid") != _field(
        other["EventReport"][0], "uuid"
    )


def test_description_report_uuid_is_deterministic_uuid5():
    assert description_report_uuid(EVENT_UUID) == description_report_uuid(EVENT_UUID)
    assert description_report_uuid(EVENT_UUID) != description_report_uuid(
        OTHER_EVENT_UUID
    )


# --- API handler: create -----------------------------------------------------


def test_create_event_adds_the_description_report_before_publishing(
    api_handler, helper, config
):
    config.misp.publish_on_create = True
    event_data = _event_data_with_description(helper, config)
    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": REPORT_NAME}
    }
    api_handler.misp.add_event_report.return_value = {"EventReport": {"id": "9"}}

    result = api_handler.create_event(event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.add_event_report.assert_called_once()
    event_id, report = api_handler.misp.add_event_report.call_args[0]
    assert event_id == "1"
    assert isinstance(report, MISPEventReport)
    assert report.name == REPORT_NAME
    assert report.content == DESCRIPTION
    assert report.uuid == description_report_uuid(EVENT_UUID)
    assert report.distribution == 2
    api_handler.misp.update_event_report.assert_not_called()

    method_calls = [c[0] for c in api_handler.misp.mock_calls]
    assert method_calls.index("add_event_report") < method_calls.index("publish")


def test_create_event_does_not_send_the_report_in_the_event_payload(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config)
    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": REPORT_NAME}
    }

    api_handler.create_event(event_data)

    sent_event = api_handler.misp.add_event.call_args[0][0]
    assert not sent_event.event_reports


def test_create_event_without_description_makes_no_report_call(
    api_handler, helper, config
):
    event_data = _convert(helper, config, _bundle())
    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": REPORT_NAME}
    }

    result = api_handler.create_event(event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()


@pytest.mark.parametrize(
    "side_effect",
    [
        {"return_value": {"errors": ["Event report could not be saved"]}},
        {"side_effect": RuntimeError("boom")},
    ],
    ids=["errors-response", "exception"],
)
def test_create_event_survives_a_failing_report_call(
    api_handler, helper, config, side_effect
):
    config.misp.publish_on_create = True
    event_data = _event_data_with_description(helper, config)
    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": REPORT_NAME}
    }
    api_handler.misp.add_event_report.configure_mock(**side_effect)

    result = api_handler.create_event(event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.publish.assert_called_once()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert "event report" in message
    assert meta["report_uuid"] == description_report_uuid(EVENT_UUID)
    assert meta["event_id"] == "1"


# --- API handler: update -----------------------------------------------------


def _prepare_update(api_handler, existing_event):
    api_handler.misp.get_event.return_value = existing_event
    api_handler.misp.update_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": REPORT_NAME}
    }


def test_update_event_adds_the_report_when_none_exists(api_handler, helper, config):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event())
    api_handler.misp.add_event_report.return_value = {"EventReport": {"id": "9"}}

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.add_event_report.assert_called_once()
    event_id, report = api_handler.misp.add_event_report.call_args[0]
    assert event_id == "1"
    assert report.uuid == description_report_uuid(EVENT_UUID)
    assert report.content == DESCRIPTION
    api_handler.misp.update_event_report.assert_not_called()

    method_calls = [c[0] for c in api_handler.misp.mock_calls]
    assert method_calls.index("update_event") < method_calls.index("add_event_report")
    assert method_calls.index("add_event_report") < method_calls.index("publish")


def test_update_event_updates_the_report_in_place_when_content_changed(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(api_handler, _existing_event([_existing_report("Old content")]))
    api_handler.misp.update_event_report.return_value = {"EventReport": {"id": "7"}}

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_called_once()
    (report,) = api_handler.misp.update_event_report.call_args[0]
    assert report.id == 7
    assert report.content == "New description"
    assert report.name == REPORT_NAME


def test_update_event_updates_the_report_when_container_was_renamed(
    api_handler, helper, config
):
    event_data = _convert(
        helper, config, _bundle(name="Renamed container", description=DESCRIPTION)
    )
    _prepare_update(api_handler, _existing_event([_existing_report()]))

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.add_event_report.assert_not_called()
    (report,) = api_handler.misp.update_event_report.call_args[0]
    assert report.name == "Renamed container"


RESTORE_URL = "eventReports/restore/7"
RESTORE_OK = {
    "saved": True,
    "success": True,
    "message": "Event Report 7 restored",
}


def _method_calls(api_handler):
    return [c[0] for c in api_handler.misp.mock_calls]


def test_update_event_restores_a_deleted_report_without_updating_it(
    api_handler, helper, config
):
    """eventReports/edit ignores "deleted": use the restore endpoint only."""
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event([_existing_report(deleted=True)]))
    api_handler.misp.direct_call.return_value = RESTORE_OK

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.direct_call.assert_called_once_with(RESTORE_URL, {})
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    api_handler.misp.get_event_report.assert_not_called()
    helper.connector_logger.warning.assert_not_called()
    meta = helper.connector_logger.info.call_args[1]["meta"]
    assert meta["action"] == "restore"
    assert meta["report_id"] == 7
    assert meta["report_uuid"] == description_report_uuid(EVENT_UUID)


def test_update_event_restores_then_updates_a_deleted_report_with_new_content(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(
        api_handler,
        _existing_event([_existing_report("Old content", deleted=True)]),
    )
    api_handler.misp.direct_call.return_value = RESTORE_OK
    api_handler.misp.update_event_report.return_value = {"EventReport": {"id": "7"}}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.direct_call.assert_called_once_with(RESTORE_URL, {})
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_called_once()
    (report,) = api_handler.misp.update_event_report.call_args[0]
    assert report.id == 7
    assert report.content == "New description"
    method_calls = _method_calls(api_handler)
    assert method_calls.index("direct_call") < method_calls.index("update_event_report")
    helper.connector_logger.warning.assert_not_called()


def test_update_event_does_not_restore_a_report_that_is_not_deleted(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(api_handler, _existing_event([_existing_report("Old content")]))

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.direct_call.assert_not_called()
    api_handler.misp.update_event_report.assert_called_once()


def test_update_event_makes_no_report_call_when_report_is_identical(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event([_existing_report()]))

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    api_handler.misp.get_event_report.assert_not_called()


def test_update_event_makes_no_report_call_when_only_whitespace_differs(
    api_handler, helper, config
):
    event_data = _convert(helper, config, _bundle(description="x"))
    event_data["EventReport"] = [
        {
            "name": REPORT_NAME,
            "content": "x\n",
            "uuid": description_report_uuid(EVENT_UUID),
            "distribution": 2,
        }
    ]
    _prepare_update(api_handler, _existing_event([_existing_report("x")]))

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()


def test_update_event_updates_the_report_when_only_distribution_differs(
    api_handler, helper, config
):
    """The report follows MISP_DISTRIBUTION_LEVEL (e.g. 0 -> 2)."""
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event([_existing_report(distribution=0)]))
    api_handler.misp.update_event_report.return_value = {"EventReport": {"id": "7"}}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_called_once()
    (report,) = api_handler.misp.update_event_report.call_args[0]
    assert report.id == 7
    assert report.distribution == 2
    assert report.name == REPORT_NAME
    assert report.content == DESCRIPTION
    helper.connector_logger.warning.assert_not_called()


@pytest.mark.parametrize("existing_distribution", [2, "2"])
def test_update_event_makes_no_report_call_when_distribution_is_identical(
    api_handler, helper, config, existing_distribution
):
    event_data = _event_data_with_description(helper, config)
    report = _existing_report()
    # MISPEventReport casts the distribution to int: force a raw string
    report.distribution = existing_distribution
    _prepare_update(api_handler, _existing_event([report]))

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()


def test_sync_event_reports_ignores_a_missing_desired_distribution(api_handler):
    existing = _existing_report(distribution=0)

    api_handler._sync_event_reports(
        "1",
        [
            {
                "name": REPORT_NAME,
                "content": DESCRIPTION,
                "uuid": description_report_uuid(EVENT_UUID),
            }
        ],
        existing_reports=[existing],
    )

    api_handler.misp.update_event_report.assert_not_called()
    assert existing.distribution == 0


def test_update_event_restores_then_updates_a_deleted_report_with_new_distribution(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config)
    _prepare_update(
        api_handler,
        _existing_event([_existing_report(distribution=0, deleted=True)]),
    )
    api_handler.misp.direct_call.return_value = RESTORE_OK
    api_handler.misp.update_event_report.return_value = {"EventReport": {"id": "7"}}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.direct_call.assert_called_once_with(RESTORE_URL, {})
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_called_once()
    (report,) = api_handler.misp.update_event_report.call_args[0]
    assert report.distribution == 2
    method_calls = _method_calls(api_handler)
    assert method_calls.index("direct_call") < method_calls.index("update_event_report")
    helper.connector_logger.warning.assert_not_called()


def test_update_event_ignores_reports_with_another_uuid(api_handler, helper, config):
    event_data = _event_data_with_description(helper, config)
    other = MISPEventReport()
    other.from_dict(id=3, name="Analyst notes", content="manual", uuid=OTHER_EVENT_UUID)
    _prepare_update(api_handler, _existing_event([other]))

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.add_event_report.assert_called_once()
    api_handler.misp.update_event_report.assert_not_called()
    assert other.content == "manual"


def test_update_event_restores_a_report_hidden_from_the_event(
    api_handler, helper, config
):
    """A soft-deleted report is absent from the event: restore it, do not re-add."""
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event())
    api_handler.misp.get_event_report.return_value = _existing_report(deleted=True)
    api_handler.misp.direct_call.return_value = RESTORE_OK

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.get_event_report.assert_called_once_with(
        description_report_uuid(EVENT_UUID), pythonify=True
    )
    api_handler.misp.direct_call.assert_called_once_with(RESTORE_URL, {})
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    helper.connector_logger.warning.assert_not_called()


def test_update_event_restores_then_updates_a_hidden_report_with_new_content(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(api_handler, _existing_event())
    api_handler.misp.get_event_report.return_value = _existing_report(
        "Old content", deleted=True
    )
    api_handler.misp.direct_call.return_value = RESTORE_OK
    api_handler.misp.update_event_report.return_value = {"EventReport": {"id": "7"}}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.direct_call.assert_called_once_with(RESTORE_URL, {})
    api_handler.misp.add_event_report.assert_not_called()
    (report,) = api_handler.misp.update_event_report.call_args[0]
    assert report.id == 7
    assert report.content == "New description"
    method_calls = _method_calls(api_handler)
    assert method_calls.index("direct_call") < method_calls.index("update_event_report")
    helper.connector_logger.warning.assert_not_called()


@pytest.mark.parametrize(
    "side_effect",
    [
        {"return_value": {"errors": ["Event report could not be restored"]}},
        {"side_effect": RuntimeError("boom")},
    ],
    ids=["errors-response", "exception"],
)
@pytest.mark.parametrize("hidden", [False, True], ids=["in-event", "hidden"])
def test_update_event_survives_a_failing_restore(
    api_handler, helper, config, side_effect, hidden
):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config, "New description")
    deleted_report = _existing_report("Old content", deleted=True)
    if hidden:
        _prepare_update(api_handler, _existing_event())
        api_handler.misp.get_event_report.return_value = deleted_report
    else:
        _prepare_update(api_handler, _existing_event([deleted_report]))
    api_handler.misp.direct_call.configure_mock(**side_effect)

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.publish.assert_called_once()
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert "restore" in message
    assert meta["event_id"] == "1"
    assert meta["report_uuid"] == description_report_uuid(EVENT_UUID)
    assert meta["report_id"] == 7
    assert meta["error"]


@pytest.mark.parametrize(
    ("response", "expected_error"),
    [
        ("<html>Proxy page</html>", "str"),
        ({"saved": False}, "saved"),
        ({"saved": True, "success": False}, "success"),
        ({"saved": True, "success": "true"}, "success"),
    ],
    ids=["string", "dict-without-success", "success-false", "success-not-true"],
)
def test_update_event_treats_a_non_success_restore_response_as_failed(
    api_handler, helper, config, response, expected_error
):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(
        api_handler,
        _existing_event([_existing_report("Old content", deleted=True)]),
    )
    api_handler.misp.direct_call.return_value = response

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.direct_call.assert_called_once_with(RESTORE_URL, {})
    api_handler.misp.publish.assert_called_once()
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    info_messages = [c[0][0] for c in helper.connector_logger.info.call_args_list]
    assert "Successfully synced MISP event report" not in info_messages
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert message == "Failed to restore MISP event report"
    assert meta["report_id"] == 7
    assert expected_error in meta["error"]
    if isinstance(response, str):
        assert response not in meta["error"]


def test_update_event_does_not_restore_a_deleted_report_without_id(
    api_handler, helper, config
):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config, "New description")
    deleted_report = MISPEventReport()
    deleted_report.from_dict(
        name=REPORT_NAME,
        content="Old content",
        uuid=description_report_uuid(EVENT_UUID),
        deleted=True,
    )
    assert getattr(deleted_report, "id", None) is None
    _prepare_update(api_handler, _existing_event([deleted_report]))

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.direct_call.assert_not_called()
    api_handler.misp.publish.assert_called_once()
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert message == "Failed to restore MISP event report"
    assert meta["report_id"] is None
    assert meta["report_uuid"] == description_report_uuid(EVENT_UUID)
    assert "no id" in meta["error"]


def test_update_event_adds_the_report_when_lookup_finds_nothing(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event())
    api_handler.misp.get_event_report.return_value = {"errors": ["Invalid report"]}
    api_handler.misp.add_event_report.return_value = {"EventReport": {"id": "9"}}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.get_event_report.assert_called_once()
    api_handler.misp.add_event_report.assert_called_once()
    api_handler.misp.update_event_report.assert_not_called()
    helper.connector_logger.warning.assert_not_called()


def test_update_event_adds_the_report_and_warns_when_lookup_raises(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _existing_event())
    api_handler.misp.get_event_report.side_effect = RuntimeError("boom")
    api_handler.misp.add_event_report.return_value = {"EventReport": {"id": "9"}}

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.add_event_report.assert_called_once()
    api_handler.misp.update_event_report.assert_not_called()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert "look up" in message
    assert meta["report_uuid"] == description_report_uuid(EVENT_UUID)
    assert meta["error"] == "boom"


def test_create_event_does_not_look_up_the_report(api_handler, helper, config):
    event_data = _event_data_with_description(helper, config)
    api_handler.misp.add_event.return_value = {
        "Event": {"id": "1", "uuid": EVENT_UUID, "info": REPORT_NAME}
    }

    api_handler.create_event(event_data)

    api_handler.misp.get_event_report.assert_not_called()
    api_handler.misp.add_event_report.assert_called_once()


@pytest.mark.parametrize(
    "side_effect",
    [
        {"return_value": {"errors": ["Event report could not be saved"]}},
        {"side_effect": RuntimeError("boom")},
    ],
    ids=["errors-response", "exception"],
)
def test_update_event_survives_a_failing_report_call(
    api_handler, helper, config, side_effect
):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(api_handler, _existing_event([_existing_report("Old content")]))
    api_handler.misp.update_event_report.configure_mock(**side_effect)

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.publish.assert_called_once()
    helper.connector_logger.warning.assert_called_once()
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert meta["report_uuid"] == description_report_uuid(EVENT_UUID)


def test_sync_event_reports_accepts_plain_dicts(api_handler):
    report_uuid = description_report_uuid(EVENT_UUID)
    api_handler.misp.add_event_report.return_value = {"EventReport": {"id": "9"}}

    api_handler._sync_event_reports(
        "1", [{"name": "n", "content": "c", "uuid": report_uuid, "distribution": 1}]
    )

    event_id, report = api_handler.misp.add_event_report.call_args[0]
    assert event_id == "1"
    assert (report.name, report.content, report.uuid) == ("n", "c", report_uuid)
    assert api_handler.misp.mock_calls[-1] == call.add_event_report("1", report)


def test_update_event_skips_a_hidden_report_of_another_event(
    api_handler, helper, config
):
    """In round-trip mode the report UUID can be taken by another event."""
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config, "New description")
    _prepare_update(api_handler, _existing_event())
    api_handler.misp.get_event_report.return_value = _existing_report(
        "Old content", deleted=True, event_id="42"
    )

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.direct_call.assert_not_called()
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    api_handler.misp.publish.assert_called_once()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert message == "Failed to sync MISP event report"
    assert meta["event_id"] == "1"
    assert "another MISP event" in meta["error"]
    assert "42" in meta["error"]


def test_report_lookup_drops_only_the_pymisp_not_found_error(api_handler, caplog):
    """A missing report is the normal case: PyMISP's 404 ERROR is not logged."""
    pymisp_logger = logging.getLogger("pymisp")

    def get_event_report(*args, **kwargs):
        pymisp_logger.error("Something went wrong (404): {'message': 'Invalid report'}")
        pymisp_logger.error("Something went wrong (403): {'message': 'Forbidden'}")
        return {"errors": (404, {"message": "Invalid report"})}

    api_handler.misp.get_event_report.side_effect = get_event_report

    with caplog.at_level(logging.ERROR, logger="pymisp"):
        found = api_handler._find_hidden_event_report(
            "1", description_report_uuid(EVENT_UUID), {}
        )
        pymisp_logger.error("Something went wrong (404): after the lookup")

    assert found is None
    messages = [r.getMessage() for r in caplog.records if r.name == "pymisp"]
    assert messages == [
        "Something went wrong (403): {'message': 'Forbidden'}",
        "Something went wrong (404): after the lookup",
    ]
    assert not pymisp_logger.filters


def test_sync_event_reports_skips_a_report_without_uuid(api_handler, helper):
    synced = api_handler._sync_event_reports(
        "1", [{"name": "n", "content": "c", "distribution": 1}], []
    )

    assert synced is False
    api_handler.misp.get_event_report.assert_not_called()
    api_handler.misp.add_event_report.assert_not_called()
    api_handler.misp.update_event_report.assert_not_called()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert message == "Skipped MISP event report without UUID"
    assert meta["report_name"] == "n"


# --- API handler: legacy description attribute -------------------------------

LEGACY_UUID = "55555555-5555-5555-5555-555555555555"
OTHER_COMMENT_UUID = "77777777-7777-7777-7777-777777777777"


def _event_with_legacy_attribute(reports=()):
    return _existing_event(
        reports,
        attributes=[
            _existing_attribute(LEGACY_DESCRIPTION_COMMENT, LEGACY_UUID),
            _existing_attribute("Analyst note", OTHER_COMMENT_UUID, value="note"),
        ],
    )


def test_update_event_deletes_the_legacy_description_attribute(
    api_handler, helper, config
):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _event_with_legacy_attribute())
    api_handler.misp.get_event_report.return_value = {"errors": ["Invalid report"]}
    api_handler.misp.add_event_report.return_value = {"EventReport": {"id": "9"}}
    api_handler.misp.delete_attribute.return_value = {"message": "Attribute deleted."}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.delete_attribute.assert_called_once()
    (attribute,) = api_handler.misp.delete_attribute.call_args[0]
    assert attribute.uuid == LEGACY_UUID
    method_calls = _method_calls(api_handler)
    assert method_calls.index("add_event_report") < method_calls.index(
        "delete_attribute"
    )
    assert method_calls.index("delete_attribute") < method_calls.index("publish")
    helper.connector_logger.warning.assert_not_called()


def test_update_event_deletes_the_legacy_attribute_when_report_is_unchanged(
    api_handler, helper, config
):
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _event_with_legacy_attribute([_existing_report()]))
    api_handler.misp.delete_attribute.return_value = {"message": "Attribute deleted."}

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.update_event_report.assert_not_called()
    api_handler.misp.delete_attribute.assert_called_once()


@pytest.mark.parametrize(
    "side_effect",
    [
        {"return_value": {"errors": ["Event report could not be saved"]}},
        {"side_effect": RuntimeError("boom")},
    ],
    ids=["errors-response", "exception"],
)
def test_update_event_keeps_the_legacy_attribute_when_report_sync_fails(
    api_handler, helper, config, side_effect
):
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _event_with_legacy_attribute())
    api_handler.misp.get_event_report.return_value = {"errors": ["Invalid report"]}
    api_handler.misp.add_event_report.configure_mock(**side_effect)

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.delete_attribute.assert_not_called()


def test_update_event_keeps_the_legacy_attribute_without_description(
    api_handler, helper, config
):
    event_data = _convert(helper, config, _bundle())
    _prepare_update(api_handler, _event_with_legacy_attribute())

    api_handler.update_event(EVENT_UUID, event_data)

    api_handler.misp.delete_attribute.assert_not_called()


@pytest.mark.parametrize(
    "side_effect",
    [
        {"return_value": {"errors": ["Attribute not found"]}},
        {"side_effect": RuntimeError("boom")},
    ],
    ids=["errors-response", "exception"],
)
def test_update_event_survives_a_failing_legacy_attribute_deletion(
    api_handler, helper, config, side_effect
):
    config.misp.publish_on_update = True
    event_data = _event_data_with_description(helper, config)
    _prepare_update(api_handler, _event_with_legacy_attribute([_existing_report()]))
    api_handler.misp.delete_attribute.configure_mock(**side_effect)

    result = api_handler.update_event(EVENT_UUID, event_data)

    assert result["uuid"] == EVENT_UUID
    api_handler.misp.publish.assert_called_once()
    helper.connector_logger.warning.assert_called_once()
    message = helper.connector_logger.warning.call_args[0][0]
    meta = helper.connector_logger.warning.call_args[1]["meta"]
    assert message == "Failed to delete legacy MISP description attribute"
    assert meta["attribute_uuid"] == LEGACY_UUID
    assert meta["error"]
