from unittest.mock import MagicMock

from connector.connector import RfAsiConnector
from connector.settings import ConnectorSettings
from pycti import Incident as PyctiIncident


def test_collect_intelligence_returns_incidents_author_and_marking(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    all_exposure_items,
):
    connector = RfAsiConnector(config=stub_connector_settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=all_exposure_items)
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )

    stix_objects = connector._collect_intelligence()

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    identities = [obj for obj in stix_objects if obj["type"] == "identity"]
    markings = [obj for obj in stix_objects if obj["type"] == "marking-definition"]

    assert len(incidents) == len(all_exposure_items)
    assert len(identities) == 1
    assert len(markings) == 1
    assert identities[0]["name"] == "Recorded Future ASI"
    assert markings[0]["x_opencti_definition"] == "TLP:AMBER+STRICT"

    connector.client.list_exposures.assert_called_once_with(
        project_id="test-project-id",
        limit=100,
    )
    assert connector.client.get_exposure_assets.call_count == len(all_exposure_items)
    connector.client.get_exposure_assets.assert_any_call(
        project_id="test-project-id",
        signature_id="sig-001",
        limit=100,
    )

    first_exposure = all_exposure_items[0]["signature"]
    assert incidents[0]["name"] == first_exposure["name"]
    assert incidents[0].id == PyctiIncident.generate_id(
        name=first_exposure["name"],
        created=incidents[0].created,
    )


def test_collect_intelligence_returns_empty_list_when_no_exposures(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RfAsiConnector(config=stub_connector_settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()

    stix_objects = connector._collect_intelligence()

    assert stix_objects == []
    connector.client.get_exposure_assets.assert_not_called()
