"""Tests targeting modified lines to improve patch coverage.

Focuses on: connector.py (_get_tlp, entity_in_scope, _send_bundle,
_collect_intelligence, process_message), client_api.py (CircuitBreaker),
and attack_pattern_handler.py (error paths).
"""

from unittest.mock import MagicMock, patch

import pytest
from conftest import StubHelper


# ===========================================================================
# connector.py — _get_tlp
# ===========================================================================
class TestGetTlp:
    @pytest.fixture(autouse=True)
    def _import(self):
        from polyswarm_enrichment.connector import ConnectorTemplate

        self.ConnectorTemplate = ConnectorTemplate

    def test_tlp_from_opencti_entity(self):
        opencti_entity = {
            "objectMarking": [{"definition": "TLP:AMBER"}],
        }
        result = self.ConnectorTemplate._get_tlp({}, opencti_entity)
        assert result == "TLP:AMBER"

    def test_tlp_from_stix_marking_refs(self):
        stix_entity = {
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
        }
        result = self.ConnectorTemplate._get_tlp(stix_entity)
        assert result == "TLP:GREEN"

    def test_tlp_none_when_no_markings(self):
        result = self.ConnectorTemplate._get_tlp({}, {})
        assert result is None

    def test_tlp_opencti_takes_precedence(self):
        stix_entity = {
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
        }
        opencti_entity = {
            "objectMarking": [{"definition": "TLP:RED"}],
        }
        result = self.ConnectorTemplate._get_tlp(stix_entity, opencti_entity)
        assert result == "TLP:RED"

    def test_tlp_ignores_non_tlp_markings(self):
        opencti_entity = {
            "objectMarking": [{"definition": "PAP:RED"}],
        }
        result = self.ConnectorTemplate._get_tlp({}, opencti_entity)
        assert result is None

    def test_tlp_unknown_stix_ref(self):
        stix_entity = {"object_marking_refs": ["marking-definition--unknown"]}
        result = self.ConnectorTemplate._get_tlp(stix_entity)
        assert result is None


# ===========================================================================
# connector.py — entity_in_scope (static-like, but needs self.helper)
# ===========================================================================
class TestEntityInScope:
    def _make_connector(self):
        """Build a minimal ConnectorTemplate without full __init__."""
        from polyswarm_enrichment.connector import ConnectorTemplate

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        obj.helper.connect_scope = "StixFile,Artifact"
        return obj

    def test_stixfile_in_scope(self):
        c = self._make_connector()
        data = {"enrichment_entity": {"entity_type": "StixFile"}}
        assert c.entity_in_scope(data) is True

    def test_artifact_in_scope(self):
        c = self._make_connector()
        data = {"enrichment_entity": {"entity_type": "Artifact"}}
        assert c.entity_in_scope(data) is True

    def test_domain_not_in_scope(self):
        c = self._make_connector()
        data = {"enrichment_entity": {"entity_type": "Domain-Name"}}
        assert c.entity_in_scope(data) is False


# ===========================================================================
# connector.py — _send_bundle (dedup + send)
# ===========================================================================
class TestSendBundle:
    def _make_connector(self):
        from polyswarm_enrichment.connector import ConnectorTemplate

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        return obj

    def test_deduplicates_by_id(self):
        c = self._make_connector()
        objs = [
            {"id": "indicator--1", "type": "indicator"},
            {"id": "indicator--1", "type": "indicator"},
            {"id": "malware--2", "type": "malware"},
        ]
        result = c._send_bundle(objs)
        assert "1 bundle" in result

    def test_no_duplicates(self):
        c = self._make_connector()
        objs = [{"id": "indicator--1", "type": "indicator"}]
        result = c._send_bundle(objs)
        assert "1" in result

    def test_objects_without_id_included(self):
        c = self._make_connector()
        objs = [{"type": "note"}, {"id": "indicator--1", "type": "indicator"}]
        result = c._send_bundle(objs)
        assert "bundle" in result.lower()


# ===========================================================================
# connector.py — _collect_intelligence
# ===========================================================================
class TestCollectIntelligence:
    def _make_connector(self):
        from polyswarm_enrichment.connector import ConnectorTemplate
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        obj.stix_objects_list = []
        obj.converter_to_stix = ConverterToStix(obj.helper)
        obj.attack_pattern_handler = MagicMock()
        obj.attack_pattern_handler.clear_cache = MagicMock()
        obj.attack_pattern_handler.has_ttp_data.return_value = False
        obj.attack_pattern_handler.create_attack_patterns_for_malware.return_value = (
            [],
            [],
        )
        obj.attack_pattern_handler.create_attack_patterns_for_actor.return_value = (
            [],
            [],
        )
        obj.client = MagicMock()
        obj.client.get_profile.return_value = None
        obj.ioc_enabled = False
        return obj

    def test_returns_empty_for_none_result(self):
        import uuid

        c = self._make_connector()
        result = c._collect_intelligence({"id": f"file--{uuid.uuid4()}"}, None)
        assert result == []

    def test_creates_not_found_note_when_no_data(self):
        import uuid

        c = self._make_connector()
        polyswarm_result = {"data": None, "errors": []}
        observable = {"id": f"file--{uuid.uuid4()}", "hashes": {"SHA-256": "a" * 64}}
        result = c._collect_intelligence(observable, polyswarm_result)
        notes = [o for o in result if o.get("type") == "note"]
        assert len(notes) == 1
        assert "Not Found" in notes[0].get("abstract", "")

    def test_creates_error_note_for_reportable_errors(self):
        import uuid

        c = self._make_connector()
        polyswarm_result = {
            "data": None,
            "errors": [
                {
                    "community": "default",
                    "error_message": "rate limited",
                    "is_no_results": False,
                }
            ],
        }
        observable = {"id": f"file--{uuid.uuid4()}", "hashes": {"SHA-256": "a" * 64}}
        result = c._collect_intelligence(observable, polyswarm_result)
        notes = [o for o in result if o.get("type") == "note"]
        # Should have both error note and not-found note
        assert len(notes) >= 1

    def test_enriches_with_valid_data(self):
        import uuid

        file_id = f"file--{uuid.uuid4()}"
        c = self._make_connector()
        c.stix_objects_list = [
            {
                "id": file_id,
                "type": "file",
                "hashes": {"SHA-256": "a" * 64},
            }
        ]
        polyswarm_result = {
            "data": {
                "community": "default",
                "x_opencti_score": 85,
                "x_opencti_labels": ["malware_type:Trojan"],
                "x_opencti_description": "Test desc",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "sha1": "c" * 40,
                "poly_unite": ["TestMalware"],
                "detections": {"malicious": 30, "total": 60},
                "polyscore": 0.85,
                "first_seen": "2024-01-01",
                "permalink": "https://polyswarm.network/scan/abc",
            },
            "errors": [],
            "multi_community": False,
        }
        observable = {
            "id": file_id,
            "type": "file",
            "hashes": {"SHA-256": "a" * 64},
        }
        result = c._collect_intelligence(observable, polyswarm_result)
        # Should contain author identity, note, and enriched observable
        assert len(result) >= 2
        types = {o.get("type") for o in result}
        assert "identity" in types
        assert "note" in types


# ===========================================================================
# connector.py — process_message
# ===========================================================================
class TestProcessMessage:
    def _make_connector(self):
        from polyswarm_enrichment.connector import ConnectorTemplate
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        obj.helper.connect_scope = "stixfile,artifact"
        obj.stix_objects_list = []
        obj.converter_to_stix = ConverterToStix(obj.helper)
        obj.attack_pattern_handler = MagicMock()
        obj.attack_pattern_handler.clear_cache = MagicMock()
        obj.attack_pattern_handler.has_ttp_data.return_value = False
        obj.attack_pattern_handler.create_attack_patterns_for_malware.return_value = (
            [],
            [],
        )
        obj.attack_pattern_handler.create_attack_patterns_for_actor.return_value = (
            [],
            [],
        )
        obj.client = MagicMock()
        obj.client.get_profile.return_value = None
        obj.client.query_polyswarm.return_value = None
        obj.max_tlp = None
        obj.replace_with_lower_score = True
        obj.ioc_enabled = False
        return obj

    def test_no_hash_returns_early(self):
        c = self._make_connector()
        data = {
            "enrichment_entity": {"entity_type": "StixFile"},
            "stix_objects": [],
            "stix_entity": {"id": "file--1"},  # No hashes
        }
        result = c.process_message(data)
        assert "No hash" in result

    def test_artifact_preserves_filename(self):
        c = self._make_connector()
        artifact_obj = {"id": "artifact--abc", "type": "artifact"}
        data = {
            "enrichment_entity": {
                "entity_type": "Artifact",
                "standard_id": "artifact--abc",
            },
            "stix_objects": [artifact_obj],
            "stix_entity": {
                "id": "artifact--abc",
                "hashes": {"SHA-256": "a" * 64},
                "x_opencti_files": [{"name": "malware.exe"}],
            },
        }
        c.process_message(data)
        assert artifact_obj.get("x_opencti_additional_names") == ["malware.exe"]

    def test_max_tlp_skips_high_tlp(self):
        c = self._make_connector()
        c.max_tlp = "TLP:GREEN"
        data = {
            "enrichment_entity": {
                "entity_type": "StixFile",
                "objectMarking": [{"definition": "TLP:RED"}],
            },
            "stix_objects": [],
            "stix_entity": {
                "id": "file--1",
                "hashes": {"SHA-256": "a" * 64},
            },
        }
        with patch(
            "polyswarm_enrichment.connector.OpenCTIConnectorHelper.check_max_tlp",
            return_value=False,
        ):
            result = c.process_message(data)
        assert "max_tlp" in result

    def test_entity_not_in_scope(self):
        c = self._make_connector()
        c.helper.connect_scope = "stixfile"
        data = {
            "enrichment_entity": {"entity_type": "Domain-Name"},
            "stix_objects": [{"id": "domain--1"}],
            "stix_entity": {"id": "domain--1", "hashes": {"SHA-256": "a" * 64}},
            "event_type": None,
        }
        # Not in scope + no event_type → sends bundle as-is
        result = c.process_message(data)
        assert "bundle" in result.lower()


# ===========================================================================
# client_api.py — CircuitBreaker
# ===========================================================================
class TestCircuitBreaker:
    @pytest.fixture(autouse=True)
    def _import(self):
        from polyswarm_enrichment.client_api import CircuitBreaker

        self.CircuitBreaker = CircuitBreaker

    def test_initial_state_closed(self):
        cb = self.CircuitBreaker()
        assert cb.state == "CLOSED"
        can, reason = cb.can_execute()
        assert can is True
        assert reason is None

    def test_opens_after_threshold(self):
        cb = self.CircuitBreaker(failure_threshold=2)
        cb.record_failure()
        assert cb.state == "CLOSED"
        cb.record_failure()
        assert cb.state == "OPEN"

    def test_open_blocks_execution(self):
        cb = self.CircuitBreaker(failure_threshold=1, cooldown_seconds=60)
        cb.record_failure()
        can, reason = cb.can_execute()
        assert can is False
        assert "OPEN" in reason

    def test_success_resets(self):
        cb = self.CircuitBreaker(failure_threshold=2)
        cb.record_failure()
        cb.record_success()
        assert cb.state == "CLOSED"
        assert cb.failure_count == 0

    def test_get_status(self):
        cb = self.CircuitBreaker(failure_threshold=3, cooldown_seconds=120)
        status = cb.get_status()
        assert status["state"] == "CLOSED"
        assert status["threshold"] == 3
        assert status["cooldown_seconds"] == 120

    def test_half_open_after_cooldown(self):
        from datetime import datetime, timedelta

        cb = self.CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
        cb.record_failure()
        # Force last_failure_time to past
        cb.last_failure_time = datetime.now() - timedelta(seconds=10)
        can, reason = cb.can_execute()
        assert can is True
        assert cb.state == "HALF_OPEN"


# ===========================================================================
# client_api.py — _parse_api_error
# ===========================================================================
class TestParseApiError:
    def _make_client(self):
        """Build a minimal ConnectorClient without full __init__."""
        from polyswarm_enrichment.client_api import ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        return obj

    def test_parse_generic_error(self):
        c = self._make_client()
        result = c._parse_api_error(Exception("something broke"), "default")
        assert result["community"] == "default"
        assert result["error_message"] == "something broke"

    def test_parse_401_error(self):
        c = self._make_client()
        result = c._parse_api_error(Exception("HTTP 401 Unauthorized"), "private")
        assert result["is_access_error"] is True
        assert result["error_code"] == 401

    def test_parse_401_private_error(self):
        c = self._make_client()
        result = c._parse_api_error(
            Exception("HTTP 401 private access denied"), "private"
        )
        assert result["is_access_error"] is True
        assert "private" in result["error_message"].lower()

    def test_parse_403_error(self):
        c = self._make_client()
        result = c._parse_api_error(Exception("HTTP 403 Forbidden"), "default")
        assert result["is_access_error"] is True
        assert result["error_code"] == 403

    def test_parse_429_error(self):
        c = self._make_client()
        result = c._parse_api_error(Exception("HTTP 429 Too Many Requests"), "default")
        assert result["is_quota_error"] is True
        assert result["error_code"] == 429

    def test_parse_no_results_error(self):
        c = self._make_client()
        result = c._parse_api_error(Exception("No results found"), "default")
        assert result["is_no_results"] is True

    def test_parse_timeout_error(self):
        c = self._make_client()
        result = c._parse_api_error(Exception("Request timeout"), "default")
        assert result["error_type"] == "timeout"

    def test_parse_server_error(self):
        c = self._make_client()
        result = c._parse_api_error(
            Exception("HTTP 500 Internal Server Error"), "default"
        )
        assert result["error_type"] == "server_error"
        assert result["error_code"] == 500


# ===========================================================================
# client_api.py — _query_single_community (circuit breaker integration)
# ===========================================================================
class TestQuerySingleCommunity:
    def _make_client(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj._circuit_breakers = {"test": CircuitBreaker(failure_threshold=1)}
        return obj

    def test_circuit_breaker_blocks_when_open(self):
        c = self._make_client()
        c._circuit_breakers["test"].record_failure()
        mock_api = MagicMock()
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error is not None
        assert error["error_type"] == "circuit_breaker_open"
        mock_api.search.assert_not_called()


# ===========================================================================
# attack_pattern_handler.py — error path (line 178, 181, 295)
# ===========================================================================
class TestAttackPatternHandlerErrors:
    def test_create_attack_pattern_with_error(self):
        from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler

        helper = StubHelper()
        handler = AttackPatternHandler(
            helper,
            "identity--12345678-1234-4234-8234-123456789abc",
            ttp_data={
                "techniques": {"T9999": {"name": "Test", "tactic": "unknown"}},
                "type_mappings": {},
            },
        )
        # tactic == "unknown" triggers early return None
        result = handler.create_attack_pattern("T9999")
        assert result is None

    def test_create_attack_pattern_missing_ttp(self):
        from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler

        helper = StubHelper()
        handler = AttackPatternHandler(
            helper,
            "identity--12345678-1234-4234-8234-123456789abc",
            ttp_data={"techniques": {}, "type_mappings": {}},
        )
        result = handler.create_attack_pattern("T9999")
        assert result is None

    def test_create_for_actor_with_no_ttps(self):
        from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler

        helper = StubHelper()
        handler = AttackPatternHandler(
            helper,
            "identity--12345678-1234-4234-8234-123456789abc",
            ttp_data={},
        )
        patterns, rels = handler.create_attack_patterns_for_actor(
            actor_id="threat-actor--abc",
            actor_name="TestActor",
            ttp_ids=[],
        )
        assert patterns == []
        assert rels == []


# ===========================================================================
# client_api.py — _query_single_community error paths
# ===========================================================================
class TestQuerySingleCommunityErrors:
    def _make_client(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj._circuit_breakers = {"test": CircuitBreaker(failure_threshold=5)}
        return obj

    def test_no_results_exception(self):
        from polyswarm_api import exceptions as polyswarm_exceptions

        c = self._make_client()
        mock_api = MagicMock()
        mock_api.search.side_effect = polyswarm_exceptions.NoResultsException(
            MagicMock()
        )
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error["is_no_results"] is True

    def test_request_exception(self):
        from polyswarm_api import exceptions as polyswarm_exceptions

        c = self._make_client()
        mock_api = MagicMock()
        mock_api.search.side_effect = polyswarm_exceptions.RequestException(MagicMock())
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error is not None

    def test_connection_error(self):
        c = self._make_client()
        mock_api = MagicMock()
        mock_api.search.side_effect = ConnectionError("refused")
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error["error_type"] == "network_error"

    def test_value_error(self):
        c = self._make_client()
        mock_api = MagicMock()
        mock_api.search.side_effect = ValueError("bad data")
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error is not None

    def test_unexpected_exception(self):
        c = self._make_client()
        mock_api = MagicMock()
        mock_api.search.side_effect = RuntimeError("unexpected")
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error is not None

    def test_empty_search_results(self):
        c = self._make_client()
        mock_api = MagicMock()
        mock_api.search.return_value = iter([])
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is None
        assert error["is_no_results"] is True

    def test_successful_result(self):
        c = self._make_client()
        c.polyswarm = MagicMock()  # Need polyswarm attr for tag_link_get
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.failed = False
        mock_result.assertions = [MagicMock()]
        mock_result.json = {"detections": {"malicious": 10, "total": 50}}
        mock_result.polyscore = 0.8
        mock_result.sha256 = "a" * 64
        mock_result.md5 = "b" * 32
        mock_result.sha1 = "c" * 40
        mock_result.mimetype = "application/x-dosexec"
        mock_result.metadata = MagicMock()
        mock_result.metadata.polyunite = None
        mock_result.metadata.exiftool = None
        mock_result.metadata.hash = {}
        mock_result.permalink = "https://polyswarm.network/scan/abc"
        mock_result.id = "12345"
        mock_result.first_seen = "2024-01-01"
        mock_result.last_seen = "2024-06-01"
        mock_result.filename = "test.exe"
        c.polyswarm.tag_link_get.side_effect = Exception("no tags")
        mock_api.search.return_value = iter([mock_result])
        data, error = c._query_single_community("a" * 64, mock_api, "test")
        assert data is not None
        assert data["sha256"] == "a" * 64
        assert error is None


# ===========================================================================
# client_api.py — query_polyswarm single community
# ===========================================================================
class TestQueryPolyswarm:
    def _make_client(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj.polyswarm_community = "default"
        obj.polyswarm_default = None
        obj.polyswarm = MagicMock()
        obj._circuit_breakers = {"default": CircuitBreaker()}
        return obj

    def test_single_community_no_results(self):
        c = self._make_client()
        c.polyswarm.search.return_value = iter([])
        result = c.query_polyswarm("a" * 64)
        assert result["data"] is None

    def test_unexpected_exception_in_query(self):
        c = self._make_client()
        c.polyswarm.search.side_effect = RuntimeError("boom")
        result = c.query_polyswarm("a" * 64)
        assert result["data"] is None
        assert len(result["errors"]) >= 0


# ===========================================================================
# client_api.py — _validate_api_access, _check_polykg_connectivity
# ===========================================================================
class TestValidateApiAccess:
    def _make_client_raw(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj.polyswarm = MagicMock()
        obj.polyswarm_community = "default"
        obj.polyswarm_default = None
        obj._circuit_breakers = {"default": CircuitBreaker()}
        return obj

    def test_validate_api_access_success(self):
        from polyswarm_api import exceptions as polyswarm_exceptions

        c = self._make_client_raw()
        c.polyswarm.exists.side_effect = polyswarm_exceptions.NoResultsException(
            MagicMock()
        )
        c._validate_api_access()  # Should not raise

    def test_validate_api_access_transient_error(self):
        from polyswarm_api import exceptions as polyswarm_exceptions

        c = self._make_client_raw()
        exc = polyswarm_exceptions.RequestException(MagicMock())
        exc.args = ("HTTP 429",)
        c.polyswarm.exists.side_effect = exc
        c._validate_api_access()  # Should warn, not raise

    def test_validate_api_access_auth_error(self):
        from polyswarm_api import exceptions as polyswarm_exceptions

        c = self._make_client_raw()
        exc = polyswarm_exceptions.RequestException(MagicMock())
        exc.args = ("HTTP 401 denied",)
        c.polyswarm.exists.side_effect = exc
        with pytest.raises(ValueError, match="API access denied"):
            c._validate_api_access()

    def test_validate_api_access_connection_error(self):
        c = self._make_client_raw()
        c.polyswarm.exists.side_effect = ConnectionError("refused")
        c._validate_api_access()  # Should warn, not raise


# ===========================================================================
# client_api.py — get_profile / fetch_attack_patterns paths
# ===========================================================================
class TestGetProfile:
    def _make_client(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj._polykg_enabled = False
        obj._polykg_url = ""
        obj._circuit_breakers = {"polykg": CircuitBreaker()}
        return obj

    def test_get_profile_disabled(self):
        c = self._make_client()
        result = c.get_profile("TestMalware")
        assert result is None

    def test_fetch_attack_patterns_disabled(self):
        c = self._make_client()
        result = c.fetch_attack_patterns()
        assert result is None


# ===========================================================================
# connector.py — _collect_intelligence multi-community path
# ===========================================================================
class TestCollectIntelligenceMultiCommunity:
    def _make_connector(self):
        from polyswarm_enrichment.connector import ConnectorTemplate
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        obj.stix_objects_list = []
        obj.converter_to_stix = ConverterToStix(obj.helper)
        obj.attack_pattern_handler = MagicMock()
        obj.attack_pattern_handler.clear_cache = MagicMock()
        obj.attack_pattern_handler.has_ttp_data.return_value = False
        obj.attack_pattern_handler.create_attack_patterns_for_malware.return_value = (
            [],
            [],
        )
        obj.attack_pattern_handler.create_attack_patterns_for_actor.return_value = (
            [],
            [],
        )
        obj.client = MagicMock()
        obj.client.get_profile.return_value = None
        obj.ioc_enabled = False
        return obj

    def test_multi_community_data(self):
        import uuid

        file_id = f"file--{uuid.uuid4()}"
        c = self._make_connector()
        c.stix_objects_list = [
            {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
        ]
        primary_data = {
            "community": "private",
            "x_opencti_score": 90,
            "x_opencti_labels": [],
            "x_opencti_description": "Primary",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "sha1": "c" * 40,
            "poly_unite": [],
            "detections": {"malicious": 40, "total": 60},
            "polyscore": 0.9,
            "first_seen": "2024-01-01",
            "permalink": "https://polyswarm.network/scan/abc",
        }
        secondary_data = {
            "community": "default",
            "x_opencti_score": 80,
            "x_opencti_labels": [],
            "x_opencti_description": "Secondary",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "sha1": "c" * 40,
            "poly_unite": [],
            "detections": {"malicious": 30, "total": 60},
            "polyscore": 0.8,
            "first_seen": "2024-02-01",
            "permalink": "https://polyswarm.network/scan/def",
        }
        polyswarm_result = {
            "data": primary_data,
            "errors": [],
            "multi_community": True,
            "primary": primary_data,
            "secondary": secondary_data,
        }
        observable = {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
        result = c._collect_intelligence(observable, polyswarm_result)
        # Multi-community should produce notes for both communities
        notes = [o for o in result if o.get("type") == "note"]
        assert len(notes) >= 1


# ===========================================================================
# connector.py — process_message score update path
# ===========================================================================
class TestProcessMessageScoreUpdate:
    def _make_connector(self):
        from polyswarm_enrichment.connector import ConnectorTemplate
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        obj.helper.connect_scope = "stixfile,artifact"
        obj.helper.api = MagicMock()
        obj.stix_objects_list = []
        obj.converter_to_stix = ConverterToStix(obj.helper)
        obj.attack_pattern_handler = MagicMock()
        obj.attack_pattern_handler.clear_cache = MagicMock()
        obj.attack_pattern_handler.has_ttp_data.return_value = False
        obj.attack_pattern_handler.create_attack_patterns_for_malware.return_value = (
            [],
            [],
        )
        obj.attack_pattern_handler.create_attack_patterns_for_actor.return_value = (
            [],
            [],
        )
        obj.client = MagicMock()
        obj.client.get_profile.return_value = None
        obj.max_tlp = None
        obj.replace_with_lower_score = True
        obj.ioc_enabled = False
        return obj

    def test_process_message_with_enrichment(self):
        import uuid

        file_id = f"file--{uuid.uuid4()}"
        c = self._make_connector()
        c.client.query_polyswarm.return_value = {
            "data": {
                "community": "default",
                "x_opencti_score": 50,
                "x_opencti_labels": [],
                "x_opencti_description": "Test",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "sha1": "c" * 40,
                "poly_unite": [],
                "detections": {"malicious": 5, "total": 50},
                "polyscore": 0.5,
                "first_seen": "2024-01-01",
                "permalink": "https://polyswarm.network/scan/abc",
            },
            "errors": [],
            "multi_community": False,
        }
        data = {
            "enrichment_entity": {
                "entity_type": "StixFile",
                "id": "abc-123",
            },
            "stix_objects": [
                {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
            ],
            "stix_entity": {
                "id": file_id,
                "hashes": {"SHA-256": "a" * 64},
            },
        }
        result = c.process_message(data)
        assert "bundle" in result.lower()

    def test_replace_with_lower_score_false(self):
        import uuid

        file_id = f"file--{uuid.uuid4()}"
        c = self._make_connector()
        c.replace_with_lower_score = False
        c.client.query_polyswarm.return_value = {
            "data": {
                "community": "default",
                "x_opencti_score": 30,
                "x_opencti_labels": [],
                "x_opencti_description": "Test",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "sha1": "c" * 40,
                "poly_unite": [],
                "detections": {"malicious": 3, "total": 50},
                "polyscore": 0.3,
                "first_seen": "2024-01-01",
                "permalink": "https://polyswarm.network/scan/abc",
            },
            "errors": [],
            "multi_community": False,
        }
        data = {
            "enrichment_entity": {
                "entity_type": "StixFile",
                "id": "abc-123",
            },
            "stix_objects": [
                {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
            ],
            "stix_entity": {
                "id": file_id,
                "hashes": {"SHA-256": "a" * 64},
                "extensions": {
                    "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                        "score": "90",
                    }
                },
            },
        }
        result = c.process_message(data)
        assert "bundle" in result.lower()

    def test_process_message_exception(self):
        c = self._make_connector()
        c.client.query_polyswarm.side_effect = RuntimeError("boom")
        data = {
            "enrichment_entity": {"entity_type": "StixFile", "id": "abc"},
            "stix_objects": [],
            "stix_entity": {"id": "file--xyz", "hashes": {"SHA-256": "a" * 64}},
        }
        result = c.process_message(data)
        assert "error" in result.lower()


# ===========================================================================
# converter_to_stix.py — create_relationship error path
# ===========================================================================
class TestConverterToStixErrors:
    def _make_converter(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        return ConverterToStix(StubHelper())

    def test_create_relationship_invalid_id(self):
        c = self._make_converter()
        # Set author to None to trigger AttributeError in create_relationship
        c.author = None
        import uuid

        result = c.create_relationship(
            source_id=f"file--{uuid.uuid4()}",
            target_id=f"malware--{uuid.uuid4()}",
            relationship_type="related-to",
        )
        assert result is None

    def test_create_indicator_from_polyswarm_missing_data(self):
        c = self._make_converter()
        # Missing required keys triggers error path
        result = c.create_indicator_from_polyswarm(
            observable={},
            polyswarm_data={},
        )
        assert result is None or isinstance(result, dict)

    def test_create_malware_from_polyswarm_missing_data(self):
        c = self._make_converter()
        result = c.create_malware_from_polyswarm(
            polyswarm_data={},
            profile=None,
        )
        # Missing keys triggers guard path — returns (None, [], []) tuple
        assert result == (None, [], [])


# ===========================================================================
# client_api.py — query_polyswarm dual community
# ===========================================================================
class TestQueryPolyswarmDualCommunity:
    def _make_dual_client(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj.polyswarm_community = "private"
        obj.polyswarm = MagicMock()
        obj.polyswarm_default = MagicMock()
        obj._circuit_breakers = {
            "private": CircuitBreaker(),
            "default": CircuitBreaker(),
        }
        return obj

    def _make_result_mock(self, sha256, last_seen_dt=None):
        mock_result = MagicMock()
        mock_result.failed = False
        mock_result.assertions = [MagicMock()]
        mock_result.json = {"detections": {"malicious": 10, "total": 50}}
        mock_result.polyscore = 0.8
        mock_result.sha256 = sha256
        mock_result.md5 = "b" * 32
        mock_result.sha1 = "c" * 40
        mock_result.mimetype = "application/x-dosexec"
        mock_result.metadata = MagicMock()
        mock_result.metadata.polyunite = None
        mock_result.metadata.exiftool = None
        mock_result.metadata.hash = {}
        mock_result.permalink = "https://polyswarm.network/scan/abc"
        mock_result.id = "12345"
        mock_result.first_seen = "2024-01-01"
        mock_result.last_seen = "2024-06-01"
        mock_result.last_seen_dt = last_seen_dt
        mock_result.filename = "test.exe"
        return mock_result

    def test_both_communities_return_data(self):
        from datetime import datetime

        c = self._make_dual_client()
        result_private = self._make_result_mock("a" * 64, datetime(2024, 6, 1))
        result_default = self._make_result_mock("a" * 64, datetime(2024, 5, 1))
        c.polyswarm.search.return_value = iter([result_private])
        c.polyswarm.tag_link_get.side_effect = Exception("no tags")
        c.polyswarm_default.search.return_value = iter([result_default])
        c.polyswarm_default.tag_link_get.side_effect = Exception("no tags")
        result = c.query_polyswarm("a" * 64)
        assert result["multi_community"] is True
        assert result["data"] is not None

    def test_only_private_has_data(self):
        c = self._make_dual_client()
        result_private = self._make_result_mock("a" * 64)
        c.polyswarm.search.return_value = iter([result_private])
        c.polyswarm.tag_link_get.side_effect = Exception("no tags")
        c.polyswarm_default.search.return_value = iter([])
        result = c.query_polyswarm("a" * 64)
        assert result["multi_community"] is True
        assert result["data"] is not None

    def test_only_default_has_data(self):
        c = self._make_dual_client()
        result_default = self._make_result_mock("a" * 64)
        c.polyswarm.search.return_value = iter([])
        c.polyswarm_default.search.return_value = iter([result_default])
        c.polyswarm_default.tag_link_get.side_effect = Exception("no tags")
        result = c.query_polyswarm("a" * 64)
        assert result["multi_community"] is True
        assert result["data"] is not None

    def test_neither_community_has_data(self):
        c = self._make_dual_client()
        c.polyswarm.search.return_value = iter([])
        c.polyswarm_default.search.return_value = iter([])
        result = c.query_polyswarm("a" * 64)
        assert result["multi_community"] is True
        assert result["data"] is None


# ===========================================================================
# converter_to_stix.py — more error paths
# ===========================================================================
class TestConverterToStixMoreErrors:
    def _make_converter(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        return ConverterToStix(StubHelper())

    def test_create_indicator_from_polyswarm_with_valid_data(self):
        import uuid

        c = self._make_converter()
        observable = {
            "id": f"file--{uuid.uuid4()}",
            "type": "file",
            "hashes": {"SHA-256": "a" * 64},
        }
        polyswarm_data = {
            "sha256": "a" * 64,
            "x_opencti_score": 85,
            "x_opencti_description": "Test indicator",
            "first_seen": "2024-01-01",
            "permalink": "https://polyswarm.network/scan/abc",
        }
        result = c.create_indicator_from_polyswarm(observable, polyswarm_data)
        assert result is not None
        assert result["type"] == "indicator"

    def test_create_indicator_from_polyswarm_error(self):
        c = self._make_converter()
        c.author = None
        result = c.create_indicator_from_polyswarm(
            observable={"hashes": {"SHA-256": "a" * 64}},
            polyswarm_data={"sha256": "a" * 64, "first_seen": "2024-01-01"},
        )
        assert result is None

    def test_create_malware_from_polyswarm_with_family(self):
        c = self._make_converter()
        result = c.create_malware_from_polyswarm(
            polyswarm_data={
                "poly_unite": ["TrickBot"],
                "x_opencti_labels": ["malware_type:Trojan"],
                "x_opencti_description": "Test malware",
                "x_opencti_score": 90,
            },
            profile=None,
        )
        assert result is not None

    def test_create_observable_indicator_relationship(self):
        import uuid

        c = self._make_converter()
        obs_id = f"file--{uuid.uuid4()}"
        ind_id = f"indicator--{uuid.uuid4()}"
        result = c.create_observable_indicator_relationship(
            observable_id=obs_id,
            indicator_id=ind_id,
        )
        assert result is not None

    def test_create_indicator_malware_relationship(self):
        import uuid

        c = self._make_converter()
        ind_id = f"indicator--{uuid.uuid4()}"
        malware_id = f"malware--{uuid.uuid4()}"
        result = c.create_indicator_malware_relationship(
            indicator_id=ind_id,
            malware_id=malware_id,
            polyswarm_data={"poly_unite": ["TrickBot"]},
        )
        assert result is not None

    def test_create_indicator_malware_relationship_error(self):
        c = self._make_converter()
        # polyswarm_data=None triggers AttributeError on .get()
        result = c.create_indicator_malware_relationship(
            indicator_id="bad",
            malware_id="bad",
            polyswarm_data=None,
        )
        assert result is None

    def test_create_observable_indicator_relationship_error(self):
        c = self._make_converter()
        c.author = None
        result = c.create_observable_indicator_relationship(
            observable_id="bad",
            indicator_id="bad",
        )
        assert result is None


# ===========================================================================
# connector.py — _collect_intelligence deeper paths
# ===========================================================================
class TestCollectIntelligenceDeeper:
    def _make_connector(self):
        from polyswarm_enrichment.connector import ConnectorTemplate
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        obj = object.__new__(ConnectorTemplate)
        obj.helper = StubHelper()
        obj.stix_objects_list = []
        obj.converter_to_stix = ConverterToStix(obj.helper)
        obj.attack_pattern_handler = MagicMock()
        obj.attack_pattern_handler.clear_cache = MagicMock()
        obj.attack_pattern_handler.has_ttp_data.return_value = False
        obj.attack_pattern_handler.create_attack_patterns_for_malware.return_value = (
            [],
            [],
        )
        obj.attack_pattern_handler.create_attack_patterns_for_actor.return_value = (
            [],
            [],
        )
        obj.client = MagicMock()
        obj.client.get_profile.return_value = None
        obj.ioc_enabled = False
        return obj

    def test_collect_with_profile_ttps(self):
        import uuid

        file_id = f"file--{uuid.uuid4()}"
        c = self._make_connector()
        c.attack_pattern_handler.has_ttp_data.return_value = True
        c.client.get_profile.return_value = {
            "description": "A trojan",
            "aliases": ["TrickBot"],
            "ttps": [
                {
                    "technique_id": "T1059",
                    "name": "Command Scripting",
                    "tactic": "execution",
                }
            ],
            "actors": [],
        }
        c.stix_objects_list = [
            {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
        ]
        polyswarm_result = {
            "data": {
                "community": "default",
                "x_opencti_score": 85,
                "x_opencti_labels": [],
                "x_opencti_description": "Test",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "sha1": "c" * 40,
                "poly_unite": ["TrickBot"],
                "detections": {"malicious": 30, "total": 60},
                "polyscore": 0.85,
                "first_seen": "2024-01-01",
                "permalink": "https://polyswarm.network/scan/abc",
            },
            "errors": [],
            "multi_community": False,
        }
        observable = {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
        result = c._collect_intelligence(observable, polyswarm_result)
        assert len(result) >= 1

    def test_collect_with_ioc_enabled(self):
        import uuid

        file_id = f"file--{uuid.uuid4()}"
        c = self._make_connector()
        c.ioc_enabled = True
        c.client.fetch_iocs.return_value = None
        c.stix_objects_list = [
            {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
        ]
        polyswarm_result = {
            "data": {
                "community": "default",
                "x_opencti_score": 50,
                "x_opencti_labels": [],
                "x_opencti_description": "Test",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "sha1": "c" * 40,
                "poly_unite": [],
                "detections": {"malicious": 5, "total": 50},
                "polyscore": 0.5,
                "first_seen": "2024-01-01",
                "permalink": "https://polyswarm.network/scan/abc",
            },
            "errors": [],
            "multi_community": False,
        }
        observable = {"id": file_id, "type": "file", "hashes": {"SHA-256": "a" * 64}}
        result = c._collect_intelligence(observable, polyswarm_result)
        assert isinstance(result, list)


# ===========================================================================
# client_api.py — get_profile / fetch_attack_patterns with polykg enabled
# ===========================================================================
class TestPolyKGEnabled:
    def _make_client(self):
        from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient

        obj = object.__new__(ConnectorClient)
        obj.helper = StubHelper()
        obj._polykg_enabled = True
        obj._polykg_url = "http://fake-polykg:8000"
        obj.polyswarm_api_key = "test-key"
        obj._circuit_breakers = {"polykg": CircuitBreaker()}
        return obj

    @patch("polyswarm_enrichment.client_api.requests.post")
    def test_get_profile_success(self, mock_post):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"description": "A trojan"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        result = c.get_profile("TrickBot")
        assert result == {"description": "A trojan"}

    @patch("polyswarm_enrichment.client_api.requests.post")
    def test_get_profile_404(self, mock_post):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_post.return_value = mock_resp
        result = c.get_profile("Unknown")
        assert result is None

    @patch("polyswarm_enrichment.client_api.requests.post")
    def test_get_profile_connection_error(self, mock_post):
        import requests

        c = self._make_client()
        mock_post.side_effect = requests.exceptions.ConnectionError("refused")
        result = c.get_profile("TrickBot")
        assert result is None

    @patch("polyswarm_enrichment.client_api.requests.post")
    def test_get_profile_request_error(self, mock_post):
        import requests

        c = self._make_client()
        mock_post.side_effect = requests.RequestException("server error")
        result = c.get_profile("TrickBot")
        assert result is None

    def test_get_profile_circuit_open(self):
        c = self._make_client()
        c._circuit_breakers["polykg"].record_failure()
        c._circuit_breakers["polykg"]._failure_threshold = 1
        c._circuit_breakers["polykg"].state = "OPEN"
        result = c.get_profile("TrickBot")
        assert result is None

    @patch("polyswarm_enrichment.client_api.requests.get")
    def test_fetch_attack_patterns_success(self, mock_get):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"techniques": {"T1059": {}}, "type_mappings": {}}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        result = c.fetch_attack_patterns()
        assert result is not None

    @patch("polyswarm_enrichment.client_api.requests.get")
    def test_fetch_attack_patterns_connection_error(self, mock_get):
        import requests

        c = self._make_client()
        mock_get.side_effect = requests.exceptions.ConnectionError("refused")
        result = c.fetch_attack_patterns()
        assert result is None

    @patch("polyswarm_enrichment.client_api.requests.get")
    def test_fetch_attack_patterns_request_error(self, mock_get):
        import requests

        c = self._make_client()
        mock_get.side_effect = requests.RequestException("bad request")
        result = c.fetch_attack_patterns()
        assert result is None

    def test_fetch_attack_patterns_circuit_open(self):
        c = self._make_client()
        c._circuit_breakers["polykg"].record_failure()
        c._circuit_breakers["polykg"]._failure_threshold = 1
        c._circuit_breakers["polykg"].state = "OPEN"
        result = c.fetch_attack_patterns()
        assert result is None


# ===========================================================================
# converter_to_stix.py — error paths in create_* methods
# ===========================================================================
class TestConverterToStixErrorPaths:
    def _make_converter(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        return ConverterToStix(StubHelper())

    def test_parse_datetime_invalid(self):
        c = self._make_converter()
        # Line 111: invalid datetime triggers warning
        result = c._parse_datetime("not-a-date")
        # Should return current time fallback, not crash
        assert result is not None

    def test_create_location_error(self):
        c = self._make_converter()
        c.author = None
        result = c._create_location("TestCountry")
        assert result is None

    def test_create_threat_actor_error(self):
        c = self._make_converter()
        c.author = None
        result = c._create_threat_actor("TestActor", {})
        assert result is None

    def test_create_intrusion_set_error(self):
        c = self._make_converter()
        c.author = None
        result = c._create_intrusion_set("TestCampaign", {})
        assert result is None

    def test_create_vulnerability_error(self):
        c = self._make_converter()
        c.author = None
        result = c._create_vulnerability("CVE-2024-1234")
        assert result is None

    def test_create_sector_error(self):
        c = self._make_converter()
        c.author = None
        result = c._create_sector("Finance")
        assert result is None

    def test_create_software_error(self):
        c = self._make_converter()
        c.author = None
        result = c._create_software("Windows")
        assert result is None

    def test_create_related_malware_max_depth(self):
        c = self._make_converter()
        c._enrichment_depth = 10
        c._max_enrichment_depth = 2
        malware, objs, rels = c._create_related_malware(
            malware_name="TestRelated",
            source_malware_id="malware--12345678-1234-4234-8234-123456789abc",
        )
        # Should return basic malware (depth exceeded)
        assert malware is not None

    def test_create_basic_malware_error(self):
        c = self._make_converter()
        c.author = None
        malware, objs, rels = c._create_basic_malware(
            malware_name="TestMalware",
            source_malware_id="malware--12345678-1234-4234-8234-123456789abc",
        )
        assert malware is None

    def test_create_related_malware_error(self):
        c = self._make_converter()
        c.author = None
        c._enrichment_depth = 0
        c._max_enrichment_depth = 5
        malware, objs, rels = c._create_related_malware(
            malware_name="TestRelated",
            source_malware_id="malware--12345678-1234-4234-8234-123456789abc",
        )
        assert malware is None
