import datetime

import freezegun
import pytest
import stix2
from external_import_connector import ConnectorWiz
from external_import_connector.config_variables import ConfigConnector
from pycti import OpenCTIConnectorHelper


@pytest.mark.usefixtures("mocked_requests")
@freezegun.freeze_time("2025-03-17T00:00:00Z")
def test_author(mocked_helper: OpenCTIConnectorHelper):
    connector = ConnectorWiz(config=ConfigConnector(), helper=mocked_helper)

    stix_objects = connector._collect_intelligence()

    assert len(stix_objects) == 8  # Assert all objects are collected

    author = next(
        stix_object
        for stix_object in stix_objects
        if isinstance(stix_object, stix2.Identity)
    )

    assert author == connector.converter_to_stix.author

    # Ensure all stix objects have the author
    for stix_object in stix_objects[:6]:
        assert stix_object["created_by_ref"] == author.id


@freezegun.freeze_time("2025-03-17T00:00:00Z")
@pytest.mark.usefixtures("mocked_requests")
def test_object_marking_refs(mocked_helper: OpenCTIConnectorHelper):
    connector = ConnectorWiz(config=ConfigConnector(), helper=mocked_helper)

    stix_objects = connector._collect_intelligence()

    assert len(stix_objects) == 8  # Assert all objects are collected

    tlp_marking = next(
        stix_object
        for stix_object in stix_objects
        if isinstance(stix_object, stix2.MarkingDefinition)
    )

    assert tlp_marking == connector.converter_to_stix.tlp_marking

    # Ensure all stix objects have the object_marking_refs
    for stix_object in stix_objects[:6]:
        assert stix_object["object_marking_refs"] == [tlp_marking.id]


@freezegun.freeze_time("2025-03-17T00:00:00Z")
@pytest.mark.usefixtures("mocked_requests")
def test_external_references(mocked_helper: OpenCTIConnectorHelper):
    connector = ConnectorWiz(config=ConfigConnector(), helper=mocked_helper)

    stix_objects = connector._collect_intelligence()

    assert len(stix_objects) == 8  # Assert all objects are collected

    external_reference = connector.converter_to_stix.external_reference

    # Ensure all stix objects have the external references
    assert stix_objects[0]["external_references"] == [  # Existing one
        {"source_name": "Campaign Source", "url": "https://www.url-campaign.com"}
    ]
    assert stix_objects[1]["external_references"] == [external_reference]
    assert stix_objects[2]["external_references"] == [external_reference]
    assert stix_objects[3]["external_references"] == [external_reference]
    assert stix_objects[4]["external_references"] == [external_reference]
    assert stix_objects[5]["external_references"] == [external_reference]


@pytest.mark.usefixtures("mocked_requests")
def test_send_stix2_bundle_update_argument(mocked_helper: OpenCTIConnectorHelper):
    connector = ConnectorWiz(config=ConfigConnector(), helper=mocked_helper)

    connector.process_message()

    assert not mocked_helper.send_stix2_bundle.call_args.kwargs.get("update", False)


@freezegun.freeze_time("2025-03-13T10:24:00Z")
@pytest.mark.usefixtures("mocked_requests")
def test_deprecated_modified_entity_and_state(mocked_helper: OpenCTIConnectorHelper):
    connector = ConnectorWiz(config=ConfigConnector(), helper=mocked_helper)

    entities = connector._collect_intelligence()
    assert len(entities) == 8

    mocked_helper.get_state = lambda: {"last_run": str(datetime.datetime.now())}
    entities = connector._collect_intelligence()

    # Campaign, Threat and Attack Pattern are modified before the last run, so ignore in the second run
    assert len(entities) == 5
    assert mocked_helper.connector_logger.warning.call_args.args == (
        "ISOFORMAT without timezone is deprecated and will be replaced by ISOFORMAT with timezone.",
        {"last_run": datetime.datetime.fromisoformat("2025-03-13 10:24")},
    )
