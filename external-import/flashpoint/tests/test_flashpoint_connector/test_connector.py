from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest
from flashpoint_connector.connector import FlashpointConnector


def _build_config():
    config = Mock()
    config.flashpoint.api_key.get_secret_value.return_value = "test-api-key"
    config.flashpoint.indicator_tlp = "TLP:CLEAR"
    config.flashpoint.import_start_date = datetime(2026, 1, 1, tzinfo=timezone.utc)
    config.flashpoint.import_reports = False
    config.flashpoint.import_indicators = False
    config.flashpoint.import_alerts = False
    config.flashpoint.import_communities = False
    config.flashpoint.import_ccm_alerts = False
    config.flashpoint.guess_relationships_from_reports = False
    config.flashpoint.communities_queries = []
    config.flashpoint.alert_create_related_entities = False
    config.flashpoint.fresh_ccm_alerts_only = True
    config.connector.duration_period.total_seconds.return_value = 3600
    return config


def _build_helper():
    helper = Mock()
    helper.connect_id = "test-connector-id"
    helper.connect_name = "Flashpoint"
    helper.connector_logger = Mock()
    helper.log_error = Mock()
    helper.log_warning = Mock()
    helper.get_state.return_value = {}
    helper.set_state = Mock()
    helper.force_ping = Mock()
    helper.api.work.initiate_work.return_value = "work-123"
    helper.api.work.to_processed = Mock()
    helper.api.identity.create.return_value = {
        "standard_id": "identity--flashpoint-author"
    }
    helper.stix2_create_bundle.return_value = '{"type":"bundle","objects":[]}'
    helper.send_stix2_bundle.return_value = ["bundle-1"]
    return helper


def _build_connector(config=None, helper=None):
    config = config or _build_config()
    helper = helper or _build_helper()
    with patch("flashpoint_connector.connector.FlashpointClient"):
        connector = FlashpointConnector(config, helper)
    return connector


# --- _parse_iso_datetime ---


def test_parse_iso_datetime_valid():
    result = FlashpointConnector._parse_iso_datetime("2026-03-06T12:00:00+00:00")
    assert result == datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_datetime_invalid():
    assert FlashpointConnector._parse_iso_datetime("not-a-date") is None


def test_parse_iso_datetime_none():
    assert FlashpointConnector._parse_iso_datetime(None) is None


def test_parse_iso_datetime_non_string():
    assert FlashpointConnector._parse_iso_datetime(12345) is None


# --- _get_state / _set_state ---


def test_get_state_returns_dict():
    helper = _build_helper()
    helper.get_state.return_value = {"key": "value"}
    connector = _build_connector(helper=helper)
    assert connector._get_state() == {"key": "value"}


def test_get_state_returns_empty_when_none():
    helper = _build_helper()
    helper.get_state.return_value = None
    connector = _build_connector(helper=helper)
    assert connector._get_state() == {}


def test_set_state_calls_helper():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector._set_state({"test": "state"})
    helper.set_state.assert_called_once_with({"test": "state"})
    helper.force_ping.assert_called_once()


# --- _deduplicate_stix_objects ---


def test_deduplicate_removes_duplicates():
    obj1 = Mock(id="id-1")
    obj2 = Mock(id="id-2")
    obj3 = Mock(id="id-1")  # duplicate
    result = FlashpointConnector._deduplicate_stix_objects([obj1, obj2, obj3])
    assert len(result) == 2


def test_deduplicate_keeps_objects_without_id():
    obj1 = Mock(spec=[])  # no id attribute
    obj2 = Mock(spec=[])
    result = FlashpointConnector._deduplicate_stix_objects([obj1, obj2])
    assert len(result) == 2


# --- _send_bundle ---


def test_send_bundle_success():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector._send_bundle("work-1", '{"type":"bundle"}')
    helper.send_stix2_bundle.assert_called_once_with(
        '{"type":"bundle"}', work_id="work-1"
    )


def test_send_bundle_handles_exception():
    helper = _build_helper()
    helper.send_stix2_bundle.side_effect = RuntimeError("send failed")
    connector = _build_connector(helper=helper)
    connector._send_bundle("work-1", '{"type":"bundle"}')
    helper.log_error.assert_called_once()


# --- _import_reports ---


def test_import_reports_success():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_reports.return_value = [
        {"id": "report-1", "title": "Test Report"}
    ]
    connector.converter_to_stix.convert_flashpoint_report = Mock(return_value=[])

    connector._import_reports(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once()


def test_import_reports_handles_fetch_error():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_reports.side_effect = RuntimeError("API error")

    connector._import_reports(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()
    helper.api.work.to_processed.assert_called_once()


def test_import_reports_handles_conversion_error():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_reports.return_value = [{"id": "r-1"}]
    connector.converter_to_stix.convert_flashpoint_report = Mock(
        side_effect=RuntimeError("convert failed")
    )

    connector._import_reports(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()


# --- _import_communities ---


def test_import_communities_success():
    config = _build_config()
    config.flashpoint.communities_queries = ["query1"]
    helper = _build_helper()
    connector = _build_connector(config=config, helper=helper)
    connector.client.communities_search.return_value = [{"id": "doc-1"}]
    connector.converter_to_stix.convert_communities_search = Mock(return_value=[])

    connector._import_communities(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.to_processed.assert_called_once()


def test_import_communities_handles_search_error():
    config = _build_config()
    config.flashpoint.communities_queries = ["query1"]
    helper = _build_helper()
    connector = _build_connector(config=config, helper=helper)
    connector.client.communities_search.side_effect = RuntimeError("search error")

    connector._import_communities(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()


def test_import_communities_handles_conversion_error():
    config = _build_config()
    config.flashpoint.communities_queries = ["query1"]
    helper = _build_helper()
    connector = _build_connector(config=config, helper=helper)
    connector.client.communities_search.return_value = [{"id": "doc-1"}]
    connector.converter_to_stix.convert_communities_search = Mock(
        side_effect=RuntimeError("conv error")
    )

    connector._import_communities(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()


# --- _import_indicators ---


def test_import_indicators_with_data():
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    mock_indicator_obj = Mock()
    mock_indicator_obj.to_stix2_object.return_value = {"type": "indicator", "id": "i-1"}
    mock_rel_obj = Mock()
    mock_rel_obj.to_stix2_object.return_value = {"type": "relationship", "id": "r-1"}

    converter_mock = Mock()
    converter_mock.marking = Mock()
    converter_mock.marking.id = "marking-1"
    converter_mock.marking.to_stix2_object.return_value = {"id": "marking-1"}
    converter_mock.author = Mock()
    converter_mock.author.id = "author-1"
    converter_mock.author.to_stix2_object.return_value = {"id": "author-1"}
    converter_mock.convert_indicator_to_stix.return_value = [
        mock_indicator_obj,
        mock_rel_obj,
    ]
    connector.indicator_converter_to_stix = converter_mock

    page = [{"modified_at": "2026-03-06T12:00:00+00:00"}]
    connector.client.iter_indicators_pages.return_value = [page]

    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    connector._import_indicators(start)

    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once()
    assert helper.set_state.called


def test_import_indicators_no_data():
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    converter_mock = Mock()
    converter_mock.convert_indicator_to_stix.return_value = []
    connector.indicator_converter_to_stix = converter_mock

    page = [{"modified_at": "2026-03-06T12:00:00+00:00"}]
    connector.client.iter_indicators_pages.return_value = [page]

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    # No work_id initiated because no actual objects
    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()


def test_import_indicators_cleans_legacy_state():
    helper = _build_helper()
    helper.get_state.return_value = {
        "misp_last_run": "2026-01-01T00:00:00Z",
        "misp_last_event": "evt-1",
        "misp_last_event_timestamp": "123",
    }
    connector = _build_connector(helper=helper)

    converter_mock = Mock()
    converter_mock.convert_indicator_to_stix.return_value = []
    connector.indicator_converter_to_stix = converter_mock
    connector.client.iter_indicators_pages.return_value = []

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    # Verify legacy keys were cleaned
    final_state = helper.set_state.call_args_list[-1][0][0]
    assert "misp_last_run" not in final_state
    assert "misp_last_event" not in final_state
    assert "misp_last_event_timestamp" not in final_state


def test_import_indicators_page_error():
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    connector.client.iter_indicators_pages.side_effect = RuntimeError("API error")

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.log_error.assert_called()


def test_import_indicators_per_page_state_update():
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    mock_obj = Mock()
    mock_obj.id = "ind-1"
    mock_obj.to_stix2_object.return_value = {"type": "indicator", "id": "i-1"}

    converter_mock = Mock()
    converter_mock.marking = Mock(id="m-1")
    converter_mock.marking.to_stix2_object.return_value = {"id": "m-1"}
    converter_mock.author = Mock(id="a-1")
    converter_mock.author.to_stix2_object.return_value = {"id": "a-1"}
    converter_mock.convert_indicator_to_stix.return_value = [mock_obj]
    connector.indicator_converter_to_stix = converter_mock

    page1 = [{"modified_at": "2026-03-06T12:00:00+00:00"}]
    page2 = [{"modified_at": "2026-03-06T13:00:00+00:00"}]
    connector.client.iter_indicators_pages.return_value = [page1, page2]

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    # State should have been updated multiple times (per page + final cleanup)
    assert helper.set_state.call_count >= 3


# --- _import_alerts ---


def test_import_alerts_communities_source():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-1",
            "source": "communities",
            "created_at": "2026-03-06T12:00:00Z",
            "status": "open",
            "reason": {"name": "test"},
            "highlight_text": "test",
            "resource": {
                "id": "doc-1",
                "title": "channel",
                "site": {"title": "forum"},
                "site_actor": {"names": {"handle": "actor1"}},
            },
        }
    ]
    connector.client.get_communities_doc.return_value = {
        "results": {
            "site_actor_alias": ["alias1"],
            "container_external_uri": "https://example.com",
        }
    }
    connector.converter_to_stix.alert_to_incident = Mock(return_value=[])

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.to_processed.assert_called_once()


def test_import_alerts_media_source():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-2",
            "source": "media",
            "created_at": "2026-03-06T12:00:00Z",
            "resource": {
                "id": "media-1",
                "site": {"title": "media_site"},
                "site_actor": {"names": {"handle": ""}},
            },
        }
    ]
    connector.client.get_media_doc.return_value = {
        "storage_uri": "https://storage.example.com/file",
        "media_id": "media-file-1",
    }
    connector.client.get_media.return_value = (b"content", "image/png")
    connector.converter_to_stix.alert_to_incident = Mock(return_value=[])

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.to_processed.assert_called_once()


def test_import_alerts_data_exposure_source():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-3",
            "source": "data_exposure_github",
            "created_at": "2026-03-06T12:00:00Z",
            "resource": {
                "id": "de-1",
                "source": "github",
                "repo": "my-repo",
                "owner": "org",
                "url": "https://github.com/org/repo",
                "site": {"title": ""},
                "site_actor": {"names": {"handle": ""}},
            },
        }
    ]
    connector.converter_to_stix.alert_to_incident = Mock(return_value=[])

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.to_processed.assert_called_once()


def test_import_alerts_unknown_source_skipped():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-4",
            "source": "unknown_source",
            "resource": {
                "id": "u-1",
                "site": {"title": ""},
                "site_actor": {"names": {"handle": ""}},
            },
        }
    ]

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.log_warning.assert_called()


def test_import_alerts_no_source_skipped():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [{"id": "alert-5", "source": None}]

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.log_warning.assert_called()


def test_import_alerts_fetch_error():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.side_effect = RuntimeError("fetch error")

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()


def test_import_alerts_conversion_error():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-err",
            "source": "communities",
            "resource": {
                "id": "doc-1",
                "site": {"title": "f"},
                "site_actor": {"names": {"handle": ""}},
            },
        }
    ]
    connector.client.get_communities_doc.side_effect = RuntimeError("doc error")

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()


# --- _import_ccm_alerts ---


def test_import_ccm_alerts_success():
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    sighting = Mock()
    sighting.fpid = "ccm-1"
    connector.client.get_compromised_credential_sightings.return_value = [sighting]
    connector.converter_to_stix.convert_ccm_alert_to_incident = Mock(return_value=[])

    connector._import_ccm_alerts(
        start_date=datetime(2026, 1, 1, tzinfo=timezone.utc), fresh_only=True
    )

    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "CCM alerts import completed", False
    )


def test_import_ccm_alerts_stix_error():
    from stix2.exceptions import STIXError

    helper = _build_helper()
    connector = _build_connector(helper=helper)

    sighting = Mock()
    sighting.fpid = "ccm-err"
    connector.client.get_compromised_credential_sightings.return_value = [sighting]
    connector.converter_to_stix.convert_ccm_alert_to_incident = Mock(
        side_effect=STIXError("stix error")
    )

    connector._import_ccm_alerts(
        start_date=datetime(2026, 1, 1, tzinfo=timezone.utc), fresh_only=False
    )

    helper.connector_logger.error.assert_called()
    helper.api.work.to_processed.assert_called_once()


def test_import_ccm_alerts_client_error():
    from flashpoint_client import FlashpointClientError

    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_compromised_credential_sightings.side_effect = (
        FlashpointClientError("client error")
    )

    connector._import_ccm_alerts(
        start_date=datetime(2026, 1, 1, tzinfo=timezone.utc), fresh_only=True
    )

    helper.connector_logger.error.assert_called()
    helper.api.work.to_processed.assert_called_once_with(
        "work-123",
        "An error occurred while fetching CCM alerts",
        True,
    )


# --- process_data ---


def test_process_data_all_disabled():
    helper = _build_helper()
    config = _build_config()
    connector = _build_connector(config=config, helper=helper)

    connector.process_data()

    # last_run should be set
    final_state = helper.set_state.call_args_list[-1][0][0]
    assert "last_run" in final_state


def test_process_data_with_last_run():
    helper = _build_helper()
    helper.get_state.return_value = {"last_run": "2026-03-01T00:00:00+00:00"}
    config = _build_config()
    connector = _build_connector(config=config, helper=helper)

    connector.process_data()

    final_state = helper.set_state.call_args_list[-1][0][0]
    assert "last_run" in final_state


def test_process_data_indicators_with_last_modified():
    helper = _build_helper()
    helper.get_state.return_value = {
        "indicators_last_modified": "2026-03-01T00:00:00+00:00"
    }
    config = _build_config()
    config.flashpoint.import_indicators = True
    connector = _build_connector(config=config, helper=helper)

    converter_mock = Mock()
    converter_mock.convert_indicator_to_stix.return_value = []
    connector.indicator_converter_to_stix = converter_mock
    connector.client.iter_indicators_pages.return_value = []

    connector.process_data()

    helper.connector_logger.info.assert_any_call(
        "Import Indicators enabled, going to fetch Indicators since:",
        {"since": datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)},
    )


def test_process_data_indicators_misp_migration():
    helper = _build_helper()
    helper.get_state.return_value = {"misp_last_run": "2026-02-01T00:00:00+00:00"}
    config = _build_config()
    config.flashpoint.import_indicators = True
    connector = _build_connector(config=config, helper=helper)

    converter_mock = Mock()
    converter_mock.convert_indicator_to_stix.return_value = []
    connector.indicator_converter_to_stix = converter_mock
    connector.client.iter_indicators_pages.return_value = []

    connector.process_data()

    helper.connector_logger.info.assert_any_call(
        "Import Indicators enabled, going to fetch Indicators since:",
        {"since": datetime(2026, 2, 1, 0, 0, tzinfo=timezone.utc)},
    )


def test_process_data_all_imports_enabled():
    helper = _build_helper()
    config = _build_config()
    config.flashpoint.import_reports = True
    config.flashpoint.import_indicators = True
    config.flashpoint.import_alerts = True
    config.flashpoint.import_communities = True
    config.flashpoint.import_ccm_alerts = True
    config.flashpoint.communities_queries = ["q1"]
    connector = _build_connector(config=config, helper=helper)

    # Mock all import methods
    connector._import_reports = Mock()
    connector._import_indicators = Mock()
    connector._import_alerts = Mock()
    connector._import_communities = Mock()
    connector._import_ccm_alerts = Mock()

    connector.process_data()

    connector._import_reports.assert_called_once()
    connector._import_indicators.assert_called_once()
    connector._import_alerts.assert_called_once()
    connector._import_communities.assert_called_once()
    connector._import_ccm_alerts.assert_called_once()


def test_process_data_handles_generic_error():
    helper = _build_helper()
    helper.get_state.side_effect = RuntimeError("state error")
    config = _build_config()
    connector = _build_connector(config=config, helper=helper)

    connector.process_data()

    helper.connector_logger.error.assert_called()


def test_process_data_keyboard_interrupt():
    helper = _build_helper()
    helper.get_state.side_effect = KeyboardInterrupt()
    config = _build_config()
    connector = _build_connector(config=config, helper=helper)

    with pytest.raises(SystemExit):
        connector.process_data()


# --- run ---


def test_run_calls_schedule_process():
    helper = _build_helper()
    config = _build_config()
    connector = _build_connector(config=config, helper=helper)

    connector.run()

    helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_data,
        duration_period=3600,
    )


# --- _import_indicators per-page deduplication ---


def test_import_indicators_deduplication_is_per_page():
    """
    Verify that deduplication is scoped per page, not cross-page.
    If the same auxiliary object (e.g. a relationship target) appears on two
    different pages, it must be included in both bundles so each bundle is
    self-contained.
    """
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    # Shared auxiliary object that will appear on both pages
    shared_aux = Mock()
    shared_aux.id = "malware--shared"
    shared_aux.to_stix2_object.return_value = {
        "type": "malware",
        "id": "malware--shared",
    }

    # Page 1: indicator-1 + shared_aux
    ind1 = Mock()
    ind1.id = "indicator--1"
    ind1.to_stix2_object.return_value = {"type": "indicator", "id": "indicator--1"}

    # Page 2: indicator-2 + shared_aux (same object)
    ind2 = Mock()
    ind2.id = "indicator--2"
    ind2.to_stix2_object.return_value = {"type": "indicator", "id": "indicator--2"}

    converter_mock = Mock()
    converter_mock.marking = Mock(id="marking--1")
    converter_mock.marking.to_stix2_object.return_value = {"id": "marking--1"}
    converter_mock.author = Mock(id="identity--1")
    converter_mock.author.to_stix2_object.return_value = {"id": "identity--1"}

    # First call on page 1 returns [ind1, shared_aux], second on page 2 returns [ind2, shared_aux]
    converter_mock.convert_indicator_to_stix.side_effect = [
        [ind1, shared_aux],
        [ind2, shared_aux],
    ]
    connector.indicator_converter_to_stix = converter_mock

    page1 = [{"modified_at": "2026-03-06T12:00:00+00:00"}]
    page2 = [{"modified_at": "2026-03-06T13:00:00+00:00"}]
    connector.client.iter_indicators_pages.return_value = [page1, page2]

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    # Two bundles should have been sent (one per page)
    assert helper.stix2_create_bundle.call_count == 2

    # shared_aux.to_stix2_object should have been called twice (once per page)
    assert shared_aux.to_stix2_object.call_count == 2


def test_import_indicators_deduplication_within_page():
    """
    Verify that within a single page, duplicate auxiliary objects are removed.
    """
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    # Two indicators sharing the same auxiliary object within the same page
    aux = Mock()
    aux.id = "malware--dup"
    aux.to_stix2_object.return_value = {"type": "malware", "id": "malware--dup"}

    ind1 = Mock()
    ind1.id = "indicator--a"
    ind1.to_stix2_object.return_value = {"type": "indicator", "id": "indicator--a"}

    ind2 = Mock()
    ind2.id = "indicator--b"
    ind2.to_stix2_object.return_value = {"type": "indicator", "id": "indicator--b"}

    converter_mock = Mock()
    converter_mock.marking = Mock(id="marking--1")
    converter_mock.marking.to_stix2_object.return_value = {"id": "marking--1"}
    converter_mock.author = Mock(id="identity--1")
    converter_mock.author.to_stix2_object.return_value = {"id": "identity--1"}

    # Both indicators on same page return the same aux object
    converter_mock.convert_indicator_to_stix.side_effect = [
        [ind1, aux],
        [ind2, Mock(id="malware--dup")],  # duplicate id
    ]
    connector.indicator_converter_to_stix = converter_mock

    page = [
        {"modified_at": "2026-03-06T12:00:00+00:00"},
        {"modified_at": "2026-03-06T12:01:00+00:00"},
    ]
    connector.client.iter_indicators_pages.return_value = [page]

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    # Only one bundle sent
    assert helper.stix2_create_bundle.call_count == 1

    # The bundle should contain: marking, author, ind1, ind2, aux (deduplicated)
    # = 5 objects, not 6
    bundle_call_objects = [
        call[0][0] for call in helper.stix2_create_bundle.call_args_list
    ]
    # stix2_create_bundle receives a list of stix objects
    stix_objects = bundle_call_objects[0]
    # marking + author + 2 indicators + 1 deduplicated aux = 5
    assert len(stix_objects) == 5


# --- _import_indicators edge cases ---


def test_import_indicators_keyboard_interrupt():
    helper = _build_helper()
    helper.get_state.side_effect = KeyboardInterrupt()
    connector = _build_connector(helper=helper)

    with pytest.raises(SystemExit):
        connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_import_indicators_generic_outer_error():
    helper = _build_helper()
    helper.get_state.side_effect = RuntimeError("unexpected")
    connector = _build_connector(helper=helper)

    connector._import_indicators(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.connector_logger.error.assert_called()


def test_import_indicators_page_modified_at_none():
    """When modified_at is missing from page items, last_modified stays at start_date."""
    helper = _build_helper()
    connector = _build_connector(helper=helper)

    converter_mock = Mock()
    converter_mock.convert_indicator_to_stix.return_value = []
    connector.indicator_converter_to_stix = converter_mock

    page = [{"value": "1.2.3.4"}]  # no modified_at
    connector.client.iter_indicators_pages.return_value = [page]

    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    connector._import_indicators(start)

    final_state = helper.set_state.call_args_list[-1][0][0]
    assert final_state["indicators_last_modified"] == start.isoformat()


def test_import_alerts_media_no_storage_uri():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-media-no-uri",
            "source": "media",
            "created_at": "2026-03-06T12:00:00Z",
            "resource": {
                "id": "media-2",
                "site": {"title": "media"},
                "site_actor": {"names": {"handle": ""}},
            },
        }
    ]
    connector.client.get_media_doc.return_value = {"media_id": "m-2"}
    connector.converter_to_stix.alert_to_incident = Mock(return_value=[])

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.to_processed.assert_called_once()


def test_import_alerts_media_no_content():
    helper = _build_helper()
    connector = _build_connector(helper=helper)
    connector.client.get_alerts.return_value = [
        {
            "id": "alert-media-no-content",
            "source": "media",
            "created_at": "2026-03-06T12:00:00Z",
            "resource": {
                "id": "media-3",
                "site": {"title": "media"},
                "site_actor": {"names": {"handle": ""}},
            },
        }
    ]
    connector.client.get_media_doc.return_value = {
        "storage_uri": "https://example.com/file",
        "media_id": "m-3",
    }
    connector.client.get_media.return_value = (None, "image/png")
    connector.converter_to_stix.alert_to_incident = Mock(return_value=[])

    connector._import_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc))

    helper.api.work.to_processed.assert_called_once()
