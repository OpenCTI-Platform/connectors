"""
Tests for MISP-to-MISP round-trip handling (issue #6182).

Tests the _find_existing_misp_event_uuid method and the create/update paths
when detect_round_trip mode is enabled.
"""

from unittest.mock import MagicMock, patch

import pytest
from misp_intel_connector.connector import MispIntelConnector


@pytest.fixture
def mock_config():
    """Create a mock config with detect_round_trip enabled."""
    config = MagicMock()
    config.misp.url = "https://misp.example.com"
    config.misp.detect_round_trip = True
    config.misp.hard_delete = True
    config.misp.distribution_level = 1
    config.misp.threat_level = 2
    config.misp.ssl_verify = True
    config.misp.api_key.get_secret_value.return_value = "fake-key"
    config.misp.publish_on_create = False
    config.misp.publish_on_update = False
    config.misp.publish_alert = False
    config.misp.tag_opencti = True
    config.misp.tag_prefix = "opencti:"
    config.misp.owner_org = None
    config.model_dump_pycti.return_value = {
        "opencti": {"url": "http://localhost:8080", "token": "fake-token"},
        "connector": {
            "id": "test-id",
            "type": "STREAM",
            "name": "MISP Intel",
            "scope": "misp",
            "confidence_level": 80,
            "log_level": "info",
            "live_stream_id": "test-stream-id",
            "live_stream_listen_delete": True,
            "live_stream_no_dependencies": False,
        },
    }
    return config


@pytest.fixture
def connector(mock_config):
    """Create a MispIntelConnector with mocked dependencies."""
    with patch(
        "misp_intel_connector.connector.OpenCTIConnectorHelper"
    ) as mock_helper_cls, patch(
        "misp_intel_connector.connector.MispApiHandler"
    ) as mock_api_cls:
        mock_helper = MagicMock()
        mock_helper_cls.return_value = mock_helper
        mock_api = MagicMock()
        mock_api.test_connection.return_value = True
        mock_api_cls.return_value = mock_api

        conn = MispIntelConnector(mock_config)
        conn.helper = mock_helper
        conn.api = mock_api
        return conn


def _make_container_data(external_references=None, container_id="container-uuid-1"):
    """Helper to build a fake STIX container dict."""
    data = {
        "type": "report",
        "id": f"report--{container_id}",
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "id": container_id,
                "type": "Report",
            }
        },
    }
    if external_references is not None:
        data["external_references"] = external_references
    return data


# ──────────────────────────────────────────────────────
# Tests for _find_existing_misp_event_uuid
# ──────────────────────────────────────────────────────


class TestFindExistingMispEventUuid:
    """Tests for the _find_existing_misp_event_uuid method."""

    def test_returns_uuid_when_single_misp_ref(self, connector):
        """When exactly one external_reference has source_name='misp', return its external_id."""
        container = _make_container_data(
            external_references=[
                {
                    "source_name": "misp",
                    "external_id": "original-misp-uuid-123",
                    "url": "https://misp.example.com/events/view/42",
                }
            ]
        )
        # The ref exists in MISP
        connector.api.get_event_by_uuid.return_value = {
            "id": "42",
            "uuid": "original-misp-uuid-123",
        }
        result = connector._find_existing_misp_event_uuid(container)
        assert result == "original-misp-uuid-123"

    def test_returns_uuid_case_insensitive(self, connector):
        """source_name matching should be case-insensitive."""
        container = _make_container_data(
            external_references=[
                {"source_name": "MISP", "external_id": "uuid-case-test"}
            ]
        )
        connector.api.get_event_by_uuid.return_value = {
            "id": "1",
            "uuid": "uuid-case-test",
        }
        result = connector._find_existing_misp_event_uuid(container)
        assert result == "uuid-case-test"

    def test_returns_none_when_no_external_references(self, connector):
        """When container has no external_references key, return None."""
        container = _make_container_data(external_references=None)
        result = connector._find_existing_misp_event_uuid(container)
        assert result is None

    def test_returns_none_when_empty_external_references(self, connector):
        """When external_references is an empty list, return None."""
        container = _make_container_data(external_references=[])
        result = connector._find_existing_misp_event_uuid(container)
        assert result is None

    def test_returns_none_when_no_misp_refs(self, connector):
        """When external_references exist but none have source_name='misp', return None."""
        container = _make_container_data(
            external_references=[
                {"source_name": "AlienVault", "external_id": "av-123"},
                {"source_name": "VirusTotal", "external_id": "vt-456"},
            ]
        )
        result = connector._find_existing_misp_event_uuid(container)
        assert result is None

    def test_returns_first_when_multiple_misp_refs(self, connector):
        """When multiple MISP external references exist and both are in MISP, return the first one."""
        container = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "misp-uuid-1"},
                {"source_name": "misp", "external_id": "misp-uuid-2"},
            ]
        )
        # Both exist in MISP
        connector.api.get_event_by_uuid.return_value = {"id": "1"}
        result = connector._find_existing_misp_event_uuid(container)
        assert result == "misp-uuid-1"

    def test_ignores_misp_ref_without_external_id(self, connector):
        """MISP refs without external_id should be ignored."""
        container = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": ""},
                {"source_name": "misp"},
            ]
        )
        result = connector._find_existing_misp_event_uuid(container)
        assert result is None

    def test_filters_misp_ref_among_others(self, connector):
        """Should correctly pick the MISP ref among non-MISP refs."""
        container = _make_container_data(
            external_references=[
                {"source_name": "AlienVault", "external_id": "av-123"},
                {"source_name": "misp", "external_id": "the-misp-uuid"},
                {"source_name": "VirusTotal", "external_id": "vt-456"},
            ]
        )
        connector.api.get_event_by_uuid.return_value = {
            "id": "1",
            "uuid": "the-misp-uuid",
        }
        result = connector._find_existing_misp_event_uuid(container)
        assert result == "the-misp-uuid"

    def test_returns_none_on_empty_container(self, connector):
        """When container is None or empty dict, return None."""
        assert connector._find_existing_misp_event_uuid(None) is None
        assert connector._find_existing_misp_event_uuid({}) is None

    def test_filters_out_refs_not_found_in_misp(self, connector):
        """MISP refs whose event no longer exists in MISP should be filtered out."""
        container = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "deleted-uuid"},
            ]
        )
        # Event does not exist in MISP
        connector.api.get_event_by_uuid.return_value = None
        result = connector._find_existing_misp_event_uuid(container)
        assert result is None
        connector.api.get_event_by_uuid.assert_called_once_with("deleted-uuid")

    def test_filters_deleted_keeps_existing(self, connector):
        """When one MISP ref is deleted and another exists, return the existing one."""
        container = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "deleted-uuid"},
                {"source_name": "misp", "external_id": "alive-uuid"},
            ]
        )
        connector.api.get_event_by_uuid.side_effect = [
            None,  # deleted-uuid not found
            {"id": "42", "uuid": "alive-uuid"},  # alive-uuid exists
        ]
        result = connector._find_existing_misp_event_uuid(container)
        assert result == "alive-uuid"

    def test_all_refs_deleted_returns_none(self, connector):
        """When all MISP refs point to deleted events, return None."""
        container = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "gone-1"},
                {"source_name": "misp", "external_id": "gone-2"},
            ]
        )
        connector.api.get_event_by_uuid.return_value = None
        result = connector._find_existing_misp_event_uuid(container)
        assert result is None
        assert connector.api.get_event_by_uuid.call_count == 2


# ──────────────────────────────────────────────────────
# Tests for _create_misp_event with detect_round_trip
# ──────────────────────────────────────────────────────


class TestCreateMispEventRoundTrip:
    """Tests for the detect_round_trip block in _create_misp_event."""

    def test_updates_existing_event_instead_of_creating(self, connector):
        """When detect_round_trip=True and a MISP ref exists, should update, not create."""
        container_data = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "existing-misp-uuid"}
            ],
            container_id="opencti-container-id",
        )
        connector.helper.get_attribute_in_extension.return_value = (
            "opencti-container-id"
        )
        # get_event_by_uuid is called in _find_existing_misp_event_uuid
        # to verify event exists in MISP (no redundant second call needed)
        connector.api.get_event_by_uuid.return_value = {
            "id": "42",
            "uuid": "existing-misp-uuid",
        }
        connector._update_misp_event = MagicMock(return_value=True)
        connector._resolve_container_references = MagicMock()

        connector._create_misp_event(container_data)

        # Should update the existing event
        connector._update_misp_event.assert_called_once_with(
            container_data, "existing-misp-uuid"
        )
        # Should NOT resolve references or create a new event
        connector._resolve_container_references.assert_not_called()
        connector.api.create_event.assert_not_called()

    def test_creates_normally_when_detect_round_trip_disabled(self, connector):
        """When detect_round_trip=False, should follow normal create path."""
        connector.config.misp.detect_round_trip = False
        container_data = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "existing-misp-uuid"}
            ],
            container_id="opencti-container-id",
        )
        connector.helper.get_attribute_in_extension.return_value = (
            "opencti-container-id"
        )
        connector._resolve_container_references = MagicMock(
            return_value={"type": "bundle", "objects": []}
        )

        with patch(
            "misp_intel_connector.connector.convert_stix_bundle_to_misp_event"
        ) as mock_convert:
            mock_convert.return_value = {"info": "test", "uuid": "opencti-container-id"}
            connector.api.create_event.return_value = {
                "id": "99",
                "uuid": "opencti-container-id",
            }
            connector.helper.api.external_reference.create.return_value = {
                "id": "ext-ref-id"
            }

            result = connector._create_misp_event(container_data)

        # Should call the normal create path
        connector._resolve_container_references.assert_called_once()
        connector.api.create_event.assert_called_once()
        assert result == {"id": "99", "uuid": "opencti-container-id"}

    def test_creates_normally_when_no_misp_ref(self, connector):
        """When detect_round_trip=True but no MISP external ref, should create normally."""
        container_data = _make_container_data(
            external_references=[],
            container_id="opencti-container-id",
        )
        connector.helper.get_attribute_in_extension.return_value = (
            "opencti-container-id"
        )
        connector._resolve_container_references = MagicMock(
            return_value={"type": "bundle", "objects": []}
        )

        with patch(
            "misp_intel_connector.connector.convert_stix_bundle_to_misp_event"
        ) as mock_convert:
            mock_convert.return_value = {"info": "test", "uuid": "opencti-container-id"}
            connector.api.create_event.return_value = {
                "id": "99",
                "uuid": "opencti-container-id",
            }
            connector.helper.api.external_reference.create.return_value = {
                "id": "ext-ref-id"
            }

            result = connector._create_misp_event(container_data)

        connector.api.create_event.assert_called_once()
        assert result is not None

    def test_creates_when_misp_event_not_found(self, connector):
        """When detect_round_trip=True and MISP ref exists but event not found in MISP, should create."""
        container_data = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "deleted-misp-uuid"}
            ],
            container_id="opencti-container-id",
        )
        connector.helper.get_attribute_in_extension.return_value = (
            "opencti-container-id"
        )
        # Event not found in MISP
        connector.api.get_event_by_uuid.return_value = None
        connector._resolve_container_references = MagicMock(
            return_value={"type": "bundle", "objects": []}
        )

        with patch(
            "misp_intel_connector.connector.convert_stix_bundle_to_misp_event"
        ) as mock_convert:
            mock_convert.return_value = {"info": "test", "uuid": "opencti-container-id"}
            connector.api.create_event.return_value = {
                "id": "99",
                "uuid": "opencti-container-id",
            }
            connector.helper.api.external_reference.create.return_value = {
                "id": "ext-ref-id"
            }

            connector._create_misp_event(container_data)

        # Should fall through to normal create
        connector.api.create_event.assert_called_once()


# ──────────────────────────────────────────────────────
# Tests for _worker_process_queue update path with detect_round_trip
# ──────────────────────────────────────────────────────


class TestWorkerUpdateRoundTrip:
    """Tests for the update path in _worker_process_queue with detect_round_trip."""

    def _run_worker_once(self, connector):
        """Run the worker, letting it process one item before stopping."""
        import threading

        processed = threading.Event()
        original_task_done = connector.work_queue.task_done

        def task_done_and_stop():
            original_task_done()
            connector.stop_worker.set()
            processed.set()

        connector.work_queue.task_done = task_done_and_stop
        connector._worker_process_queue()
        assert processed.is_set(), "Worker did not process any item"

    def test_update_uses_external_ref_uuid_when_container_uuid_not_found(
        self, connector
    ):
        """On update with detect_round_trip, should prioritize external ref UUID over container_id."""
        container_data = _make_container_data(
            external_references=[
                {"source_name": "misp", "external_id": "original-misp-uuid"}
            ],
            container_id="opencti-id",
        )
        connector.helper.get_attribute_in_extension.return_value = "opencti-id"

        # _find_existing_misp_event_uuid calls get_event_by_uuid
        # to verify the ref exists in MISP
        connector.api.get_event_by_uuid.return_value = {
            "id": "42",
            "uuid": "original-misp-uuid",
        }
        connector._update_misp_event = MagicMock(return_value=True)

        connector.work_queue.put_nowait(("update", container_data, "opencti-id"))
        self._run_worker_once(connector)

        # Should have called _update_misp_event with the external ref UUID
        connector._update_misp_event.assert_called_once_with(
            container_data, "original-misp-uuid"
        )

    def test_update_uses_container_uuid_when_found(self, connector):
        """On update, if no external ref and event found by container_id, should use it directly."""
        container_data = _make_container_data(container_id="opencti-id")
        connector.helper.get_attribute_in_extension.return_value = "opencti-id"

        connector.api.get_event_by_uuid.return_value = {
            "id": "42",
            "uuid": "opencti-id",
        }
        connector._update_misp_event = MagicMock(return_value=True)

        connector.work_queue.put_nowait(("update", container_data, "opencti-id"))
        self._run_worker_once(connector)

        # Should use the container_id directly
        connector._update_misp_event.assert_called_once_with(
            container_data, "opencti-id"
        )

    def test_update_falls_back_to_create_when_not_found_anywhere(self, connector):
        """On update, if event not found by container_id or ext ref, should create."""
        container_data = _make_container_data(
            external_references=[], container_id="opencti-id"
        )
        connector.helper.get_attribute_in_extension.return_value = "opencti-id"

        connector.api.get_event_by_uuid.return_value = None
        connector._create_misp_event = MagicMock()
        connector._update_misp_event = MagicMock()

        connector.work_queue.put_nowait(("update", container_data, "opencti-id"))
        self._run_worker_once(connector)

        connector._update_misp_event.assert_not_called()
        connector._create_misp_event.assert_called_once_with(container_data)
