from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from connector.connector import RecordedFutureAsiConnector
from connector.converter_to_stix import (
    EXPOSURE_INCIDENT_ID_ANCHOR,
    LABEL_ADDED,
    LABEL_CLEARED,
)
from connector.settings import ConnectorSettings
from pycti import Incident as PyctiIncident


def test_collect_initial_intelligence_returns_incidents_author_and_marking(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    all_exposure_items,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(return_value=all_exposure_items)
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )

    stix_objects, _ = connector._collect_initial_intelligence()

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
        first_exposure["id"],
        EXPOSURE_INCIDENT_ID_ANCHOR,
    )


def test_collect_initial_intelligence_returns_empty_list_when_no_exposures(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()

    stix_objects, _ = connector._collect_initial_intelligence()

    assert stix_objects == []
    connector.client.get_exposure_assets.assert_not_called()


def test_collect_initial_intelligence_bundle_includes_related_entities(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    all_exposure_items,
    all_exposure_assets,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(return_value=all_exposure_items[:1])
    connector.client.get_exposure_assets = MagicMock(return_value=all_exposure_assets)

    stix_objects, _ = connector._collect_initial_intelligence()

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
    assert len(relationships) == 7
    assert len(identities) == 1
    assert len(markings) == 1

    incident_id = incidents[0].id
    vulnerability_id = vulnerabilities[0].id
    related_to = [rel for rel in relationships if rel.relationship_type == "related-to"]
    observable_ids = {
        obj.id for obj in (ipv4_addresses + ipv6_addresses + domain_names)
    }
    observable_and_vulnerability_ids = observable_ids | {vulnerability_id}

    assert len(related_to) == 7

    incident_related_to = [rel for rel in related_to if rel.source_ref == incident_id]
    assert len(incident_related_to) == 4
    assert {relationship.target_ref for relationship in incident_related_to} == (
        observable_and_vulnerability_ids
    )

    observable_vulnerability_related_to = [
        rel
        for rel in related_to
        if rel.source_ref in observable_ids and rel.target_ref == vulnerability_id
    ]
    assert len(observable_vulnerability_related_to) == 3
    assert all(
        relationship.source_ref in observable_ids
        for relationship in observable_vulnerability_related_to
    )
    assert all(
        relationship.target_ref == vulnerability_id
        for relationship in observable_vulnerability_related_to
    )
    assert {
        relationship.source_ref for relationship in observable_vulnerability_related_to
    } == observable_ids


def test_collect_initial_intelligence_with_run_limit_uses_batch(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    batch_items = all_exposure_items[:1]
    connector.client.list_exposures_batch = MagicMock(
        return_value=(batch_items, "cursor-page-2")
    )
    connector.client.list_exposures = MagicMock()
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )

    stix_objects, next_cursor = connector._collect_initial_intelligence()

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


def test_collect_initial_intelligence_with_run_limit_passes_exposures_cursor(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(return_value=([], None))
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_initial_intelligence(exposures_cursor="cursor-page-2")

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


def test_process_message_logs_effective_sync_mode(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(
        run_limit=50,
        filter_severity_min="moderate",
    )
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(return_value=([], None))
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    connector.process_message()

    sync_mode_log = next(
        call
        for call in opencti_helper.connector_logger.info.call_args_list
        if call.args[0] == "[CONNECTOR] Effective sync mode"
    )
    assert sync_mode_log.args[1] == {
        "initial_sync": True,
        "run_limit": 50,
        "severity_filter": "min:moderate",
    }


def test_process_message_persists_exposures_cursor_when_batch_has_more_pages(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
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
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
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
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
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


def test_collect_initial_intelligence_passes_filter_severity_min(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(filter_severity_min="critical")
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_initial_intelligence()

    connector.client.list_exposures.assert_called_once_with(
        project_id="test-project-id",
        limit=100,
        filter_severity_min="critical",
    )


def test_collect_initial_intelligence_passes_filter_severity_exact(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(filter_severity_exact="moderate")
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_initial_intelligence()

    connector.client.list_exposures.assert_called_once_with(
        project_id="test-project-id",
        limit=100,
        filter_severity_exact="moderate",
    )


def test_collect_initial_intelligence_with_run_limit_passes_filter_severity_min(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(
        run_limit=1,
        filter_severity_min="moderate",
    )
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(return_value=([], None))
    connector.client.get_exposure_assets = MagicMock()

    connector._collect_initial_intelligence()

    connector.client.list_exposures_batch.assert_called_once_with(
        project_id="test-project-id",
        page_limit=100,
        run_limit=1,
        cursor=None,
        filter_severity_min="moderate",
    )


def test_incremental_sync_calls_history_with_last_fetch_time(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    risk_history_activity,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.get_exposure_history = MagicMock(return_value=([], []))
    connector.client.get_exposure_assets = MagicMock()
    state = {"last_fetch_time": 1717200000}

    connector._collect_incremental_intelligence(state)

    connector.client.get_exposure_history.assert_called_once_with(
        project_id="test-project-id",
        start=1717200000,
    )


def test_incremental_sync_processes_added_with_v2_enrichment(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    risk_history_activity,
    all_exposure_assets,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    added_rules = risk_history_activity["data"][0]["added_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=(added_rules, []))
    connector.client.get_exposure_assets = MagicMock(return_value=all_exposure_assets)
    state = {"last_fetch_time": 1717200000}

    stix_objects = connector._collect_incremental_intelligence(state)

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert len(incidents) == 1
    assert incidents[0]["labels"] == [LABEL_ADDED]
    assert incidents[0]["name"] == "Exposed admin panel"
    connector.client.get_exposure_assets.assert_called_once_with(
        project_id="test-project-id",
        signature_id="sig-001",
        limit=100,
    )


def test_incremental_sync_processes_removed_incident_only_no_get_exposure_assets(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    risk_history_activity,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    removed_rules = risk_history_activity["data"][0]["removed_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=([], removed_rules))
    connector.client.get_exposure_assets = MagicMock()
    state = {"last_fetch_time": 1717200000}

    stix_objects = connector._collect_incremental_intelligence(state)

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert len(incidents) == 1
    assert incidents[0]["labels"] == [LABEL_CLEARED]
    assert incidents[0]["name"] == "Open port 22"
    connector.client.get_exposure_assets.assert_not_called()


def test_process_message_incremental_sends_cleared_incident(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    risk_history_activity,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    removed_rules = risk_history_activity["data"][0]["removed_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=([], removed_rules))
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"last_fetch_time": 1717100000},
    )

    connector.process_message()

    bundle_arg = opencti_helper.stix2_create_bundle.call_args.args[0]
    incidents = [obj for obj in bundle_arg if obj["type"] == "incident"]
    assert len(incidents) == 1
    assert incidents[0]["labels"] == [LABEL_CLEARED]
    assert incidents[0]["name"] == "Open port 22"
    opencti_helper.send_stix2_bundle.assert_called_once()


def test_process_message_does_not_persist_state_on_send_failure(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    risk_history_activity,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    removed_rules = risk_history_activity["data"][0]["removed_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=([], removed_rules))
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"last_fetch_time": 1717100000},
    )
    opencti_helper.send_stix2_bundle = MagicMock(
        side_effect=RuntimeError("send failed")
    )

    connector.process_message()

    opencti_helper.set_state.assert_not_called()
    opencti_helper.api.work.to_processed.assert_called_once_with(
        "work-id", "send failed", in_error=True
    )


def test_process_message_does_not_persist_state_on_collection_failure(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.get_exposure_history = MagicMock(
        side_effect=RuntimeError("history failed")
    )
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"last_fetch_time": 1717100000},
    )

    connector.process_message()

    opencti_helper.set_state.assert_not_called()
    opencti_helper.api.work.initiate_work.assert_not_called()
    opencti_helper.api.work.to_processed.assert_not_called()


def test_process_message_does_not_persist_state_on_initial_list_exposures_failure(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(
        side_effect=RuntimeError("list exposures failed")
    )
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    connector.process_message()

    opencti_helper.set_state.assert_not_called()
    opencti_helper.api.work.initiate_work.assert_not_called()
    opencti_helper.api.work.to_processed.assert_not_called()


def test_process_message_does_not_persist_state_on_get_exposure_assets_failure(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    all_exposure_items,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(return_value=all_exposure_items)
    connector.client.get_exposure_assets = MagicMock(
        side_effect=RuntimeError("get exposure assets failed")
    )
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    connector.process_message()

    opencti_helper.set_state.assert_not_called()
    opencti_helper.api.work.initiate_work.assert_not_called()
    opencti_helper.api.work.to_processed.assert_not_called()


def test_process_message_does_not_persist_state_on_incremental_get_exposure_assets_failure(
    opencti_helper,
    make_stub_connector_settings,
    risk_history_activity,
):
    settings = make_stub_connector_settings()
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    added_rules = risk_history_activity["data"][0]["added_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=(added_rules, []))
    connector.client.get_exposure_assets = MagicMock(
        side_effect=RuntimeError("get exposure assets failed")
    )
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"last_fetch_time": 1717100000},
    )

    connector.process_message()

    opencti_helper.set_state.assert_not_called()
    opencti_helper.api.work.initiate_work.assert_not_called()
    opencti_helper.api.work.to_processed.assert_not_called()


def test_initial_sync_sets_last_fetch_time_when_zero_exposures(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    with patch("connector.connector.datetime", wraps=datetime) as mock_datetime:
        mock_datetime.now.return_value = datetime.fromtimestamp(
            1717200000, tz=timezone.utc
        )
        connector.process_message()

    saved_state = opencti_helper.set_state.call_args.args[0]
    assert saved_state["last_fetch_time"] == 1717200000
    assert saved_state["last_run"] == "2024-06-01 00:00:00"
    assert "exposures_cursor" not in saved_state
    opencti_helper.api.work.initiate_work.assert_not_called()
    connector.client.get_exposure_assets.assert_not_called()


def test_incremental_sync_applies_filter_severity_min_to_added_high_classification(
    opencti_helper,
    make_stub_connector_settings,
    risk_history_activity,
    all_exposure_assets,
):
    settings = make_stub_connector_settings(filter_severity_min="critical")
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    added_rules = risk_history_activity["data"][0]["added_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=(added_rules, []))
    connector.client.get_exposure_assets = MagicMock(return_value=all_exposure_assets)
    state = {"last_fetch_time": 1717200000}

    stix_objects = connector._collect_incremental_intelligence(state)

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert len(incidents) == 1
    connector.client.get_exposure_assets.assert_called_once()


def test_incremental_sync_skips_added_rule_below_filter_severity_min(
    opencti_helper,
    make_stub_connector_settings,
):
    settings = make_stub_connector_settings(filter_severity_min="critical")
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    added_rules = [
        {
            "id": "sig-moderate",
            "name": "Moderate exposure",
            "description": "Below critical threshold.",
            "classification": "moderate",
        }
    ]
    connector.client.get_exposure_history = MagicMock(return_value=(added_rules, []))
    connector.client.get_exposure_assets = MagicMock()
    state = {"last_fetch_time": 1717200000}

    stix_objects = connector._collect_incremental_intelligence(state)

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert incidents == []
    connector.client.get_exposure_assets.assert_not_called()


def test_incremental_sync_skips_added_rule_when_exact_filter_mismatch(
    opencti_helper,
    make_stub_connector_settings,
    risk_history_activity,
):
    settings = make_stub_connector_settings(filter_severity_exact="moderate")
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    added_rules = risk_history_activity["data"][0]["added_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=(added_rules, []))
    connector.client.get_exposure_assets = MagicMock()
    state = {"last_fetch_time": 1717200000}

    stix_objects = connector._collect_incremental_intelligence(state)

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert incidents == []
    connector.client.get_exposure_assets.assert_not_called()


def test_incremental_sync_skips_removed_rule_below_filter_severity_min(
    opencti_helper,
    make_stub_connector_settings,
    risk_history_activity,
):
    settings = make_stub_connector_settings(filter_severity_min="critical")
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    removed_rules = risk_history_activity["data"][0]["removed_rules"]
    connector.client.get_exposure_history = MagicMock(return_value=([], removed_rules))
    connector.client.get_exposure_assets = MagicMock()
    state = {"last_fetch_time": 1717200000}

    stix_objects = connector._collect_incremental_intelligence(state)

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert incidents == []


def test_incremental_sync_updates_last_fetch_time_on_success(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.get_exposure_history = MagicMock(return_value=([], []))
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={"last_fetch_time": 1717100000},
    )

    with patch("connector.connector.datetime", wraps=datetime) as mock_datetime:
        mock_datetime.now.return_value = datetime.fromtimestamp(
            1717200000, tz=timezone.utc
        )
        connector.process_message()

    saved_state = opencti_helper.set_state.call_args.args[0]
    assert saved_state["last_fetch_time"] == 1717200000
    assert saved_state["last_run"] == "2024-06-01 00:00:00"
    assert "known_exposures" not in saved_state
    opencti_helper.api.work.initiate_work.assert_not_called()
    opencti_helper.send_stix2_bundle.assert_not_called()


def test_initial_sync_sets_last_fetch_time_when_cycle_complete(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    all_exposure_items,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.list_exposures = MagicMock(return_value=all_exposure_items)
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    with patch("connector.connector.datetime", wraps=datetime) as mock_datetime:
        mock_datetime.now.return_value = datetime.fromtimestamp(
            1717200000, tz=timezone.utc
        )
        connector.process_message()

    saved_state = opencti_helper.set_state.call_args.args[0]
    assert saved_state["last_fetch_time"] == 1717200000
    assert "exposures_cursor" not in saved_state


def test_initial_sync_does_not_set_last_fetch_time_mid_batch_with_run_limit(
    opencti_helper,
    make_stub_connector_settings,
    all_exposure_items,
):
    settings = make_stub_connector_settings(run_limit=1)
    connector = RecordedFutureAsiConnector(config=settings, helper=opencti_helper)
    connector.client.list_exposures_batch = MagicMock(
        return_value=(all_exposure_items[:1], "cursor-page-2")
    )
    connector.client.get_exposure_assets = MagicMock(
        return_value={"signature": {}, "asset_exposures": []}
    )
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    with patch("connector.connector.datetime", wraps=datetime) as mock_datetime:
        mock_datetime.now.return_value = datetime.fromtimestamp(
            1717200000, tz=timezone.utc
        )
        connector.process_message()

    saved_state = opencti_helper.set_state.call_args.args[0]
    assert "last_fetch_time" not in saved_state
    assert saved_state["exposures_cursor"] == "cursor-page-2"


def test_persist_sync_state_removes_legacy_known_exposures(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    _mock_process_message_dependencies(
        opencti_helper,
        initial_state={
            "last_run": "2024-06-01 00:00:00",
            "known_exposures": {
                "sig-001": {"name": "Old", "created": "2024-06-01T00:00:00Z"}
            },
        },
    )

    connector._persist_sync_state(
        datetime(2024, 6, 2, tzinfo=timezone.utc),
        advance_fetch_time=True,
        exposures_cursor=False,
    )

    saved_state = opencti_helper.set_state.call_args.args[0]
    assert "known_exposures" not in saved_state


def test_incremental_sync_skips_removed_rule_without_id(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.get_exposure_history = MagicMock(
        return_value=([], [{"name": "Missing id"}])
    )
    connector.client.get_exposure_assets = MagicMock()

    stix_objects = connector._collect_incremental_intelligence(
        {"last_fetch_time": 1717200000}
    )

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert incidents == []


def test_incremental_sync_skips_added_rule_without_id(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.client.get_exposure_history = MagicMock(
        return_value=([{"name": "Missing id"}], [])
    )
    connector.client.get_exposure_assets = MagicMock()

    stix_objects = connector._collect_incremental_intelligence(
        {"last_fetch_time": 1717200000}
    )

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert incidents == []
    connector.client.get_exposure_assets.assert_not_called()


def test_incremental_sync_skips_added_when_also_in_removed(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
    risk_history_activity,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    added_rules = risk_history_activity["data"][0]["added_rules"]
    removed_rules = [
        {
            "id": "sig-001",
            "name": "Exposed admin panel",
            "description": "Cleared duplicate.",
            "classification": "high",
        }
    ]
    connector.client.get_exposure_history = MagicMock(
        return_value=(added_rules, removed_rules)
    )
    connector.client.get_exposure_assets = MagicMock()

    stix_objects = connector._collect_incremental_intelligence(
        {"last_fetch_time": 1717200000}
    )

    incidents = [obj for obj in stix_objects if obj["type"] == "incident"]
    assert len(incidents) == 1
    assert incidents[0]["labels"] == [LABEL_CLEARED]
    connector.client.get_exposure_assets.assert_not_called()


def test_process_message_resets_converter_caches(
    opencti_helper,
    stub_connector_settings: ConnectorSettings,
):
    connector = RecordedFutureAsiConnector(
        config=stub_connector_settings, helper=opencti_helper
    )
    connector.converter_to_stix._observable_cache[("ipv4", "1.2.3.4")] = MagicMock()
    connector.converter_to_stix._vulnerability_cache["CVE-2024-0001"] = MagicMock()
    connector.client.list_exposures = MagicMock(return_value=[])
    connector.client.get_exposure_assets = MagicMock()
    _mock_process_message_dependencies(opencti_helper, initial_state={})

    connector.process_message()

    assert connector.converter_to_stix._observable_cache == {}
    assert connector.converter_to_stix._vulnerability_cache == {}
