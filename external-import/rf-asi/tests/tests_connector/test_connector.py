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

    stix_objects, _ = connector._collect_intelligence()

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

    stix_objects, _ = connector._collect_intelligence()

    assert stix_objects == []
    connector.client.get_exposure_assets.assert_not_called()


def test_collect_intelligence_bundle_includes_related_entities(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    all_exposure_items,
    all_exposure_assets,
):
    connector = RfAsiConnector(config=stub_connector_settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=all_exposure_items[:1])
    connector.client.get_exposure_assets = MagicMock(return_value=all_exposure_assets)

    stix_objects, _ = connector._collect_intelligence()

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    ipv4_addresses = [obj for obj in stix_objects if obj["type"] == "ipv4-addr"]
    ipv6_addresses = [obj for obj in stix_objects if obj["type"] == "ipv6-addr"]
    domain_names = [obj for obj in stix_objects if obj["type"] == "domain-name"]
    vulnerabilities = [obj for obj in stix_objects if obj["type"] == "vulnerability"]
    relationships = [obj for obj in stix_objects if obj["type"] == "relationship"]
    identities = [obj for obj in stix_objects if obj["type"] == "identity"]
    markings = [obj for obj in stix_objects if obj["type"] == "marking-definition"]

    assert len(incidents) == 1
    assert len(ipv4_addresses) == 1
    assert len(ipv6_addresses) == 1
    assert len(domain_names) == 1
    assert len(vulnerabilities) == 1
    assert len(relationships) == 4
    assert len(identities) == 1
    assert len(markings) == 1

    incident_id = incidents[0].id
    related_target_refs = {relationship.target_ref for relationship in relationships}
    observable_and_vulnerability_ids = {
        obj.id
        for obj in (ipv4_addresses + ipv6_addresses + domain_names + vulnerabilities)
    }

    assert related_target_refs == observable_and_vulnerability_ids
    assert all(relationship.source_ref == incident_id for relationship in relationships)
    assert all(
        relationship.relationship_type == "related-to" for relationship in relationships
    )


def test_collect_intelligence_with_run_limit_uses_batch(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    batch_items = all_exposure_items[:1]
    connector.client.list_exposures_batch = MagicMock(
        return_value=(batch_items, "cursor-page-2")
    )
    connector.client.list_exposures = MagicMock()
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )

    stix_objects, next_cursor = connector._collect_intelligence()

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert len(incidents) == 1
    assert next_cursor == "cursor-page-2"
    connector.client.list_exposures_batch.assert_called_once_with(
        project_id="test-project-id",
        page_limit=100,
        run_limit=1,
        cursor=None,
    )
    connector.client.list_exposures.assert_not_called()
    assert connector.client.get_exposure_assets.call_count == 1


def test_collect_intelligence_with_run_limit_passes_exposures_cursor(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(return_value=([], None))
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_intelligence(exposures_cursor="cursor-page-2")

    connector.client.list_exposures_batch.assert_called_once_with(
        project_id="test-project-id",
        page_limit=100,
        run_limit=1,
        cursor="cursor-page-2",
    )


def _mock_process_message_dependencies(
    opencti_helper,
    *,
    initial_state: dict | None = None,
):
    opencti_helper.get_state = MagicMock(return_value=initial_state)
    opencti_helper.set_state = MagicMock()
    opencti_helper.api.work.initiate_work = MagicMock(return_value="work-id")
    opencti_helper.api.work.to_processed = MagicMock()
    opencti_helper.stix2_create_bundle = MagicMock(return_value="bundle")
    opencti_helper.send_stix2_bundle = MagicMock(return_value=["bundle-id"])


def test_process_message_persists_exposures_cursor_when_batch_has_more_pages(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(
        return_value=(all_exposure_items[:1], "cursor-page-2")
    )
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"last_run": "2024-01-01 00:00:00"},
    )

    connector.process_message()

    opencti_helper.set_state.assert_called_once()
    saved_state = opencti_helper.set_state.call_args.args[0]
    assert saved_state["exposures_cursor"] == "cursor-page-2"
    assert "last_run" in saved_state


def test_process_message_clears_exposures_cursor_when_cycle_complete(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(
        return_value=(all_exposure_items[:1], None)
    )
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={
            "last_run": "2024-01-01 00:00:00",
            "exposures_cursor": "cursor-page-2",
        },
    )

    connector.process_message()

    saved_state = opencti_helper.set_state.call_args.args[0]
    assert "exposures_cursor" not in saved_state
    assert "last_run" in saved_state


def test_process_message_resumes_from_stored_exposures_cursor(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(return_value=([], None))
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"exposures_cursor": "cursor-page-2"},
    )

    connector.process_message()

    connector.client.list_exposures_batch.assert_called_once_with(
        project_id="test-project-id",
        page_limit=100,
        run_limit=1,
        cursor="cursor-page-2",
    )


def test_collect_intelligence_passes_filter_severity_min(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(filter_severity_min="critical")
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_intelligence()

    connector.client.list_exposures.assert_called_once_with(
        project_id="test-project-id",
        limit=100,
        filter_severity_min="critical",
    )


def test_collect_intelligence_passes_filter_severity_exact(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(filter_severity_exact="moderate")
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_intelligence()

    connector.client.list_exposures.assert_called_once_with(
        project_id="test-project-id",
        limit=100,
        filter_severity_exact="moderate",
    )


def test_collect_intelligence_with_run_limit_passes_filter_severity_min(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(
        run_limit=1,
        filter_severity_min="moderate",
    )
    connector = RfAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(return_value=([], None))
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_intelligence()

    connector.client.list_exposures_batch.assert_called_once_with(
        project_id="test-project-id",
        page_limit=100,
        run_limit=1,
        cursor=None,
        filter_severity_min="moderate",
    )
