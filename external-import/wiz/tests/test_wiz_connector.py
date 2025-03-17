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

    assert len(stix_objects) == 7  # Assert all objects are collected

    author = next(
        stix_object
        for stix_object in stix_objects
        if isinstance(stix_object, stix2.Identity)
    )

    assert author == connector.converter_to_stix.author

    # Ensure all stix objects have the author
    for stix_object in stix_objects[:6]:
        assert stix_object["created_by_ref"] == author.id
