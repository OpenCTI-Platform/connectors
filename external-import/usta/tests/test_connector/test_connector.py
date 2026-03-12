"""Unit tests for the USTA Prodaft connector orchestrator — 100 % coverage."""

from __future__ import annotations

import sys
from datetime import timedelta
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from connector.connector import UstaProdaftConnector
from usta_client import UstaClientError


# ---- Helpers ----

def _make_config(**overrides):
    """Build a minimal mock ConnectorSettings."""
    cfg = MagicMock()
    cfg.connector.name = "USTA Test"
    cfg.connector.duration_period = timedelta(hours=1)
    prodaft = MagicMock()
    prodaft.api_base_url = "https://usta.prodaft.com"
    prodaft.api_key = "key"
    prodaft.page_size = 10
    prodaft.tlp_level = "amber"
    prodaft.confidence_level = 80
    prodaft.import_start_date = timedelta(days=7)
    prodaft.import_malicious_urls = True
    prodaft.import_phishing_sites = True
    prodaft.import_malware_hashes = True
    prodaft.import_compromised_credentials = True
    prodaft.import_credit_cards = True
    for k, v in overrides.items():
        setattr(prodaft, k, v)
    cfg.usta_prodaft = prodaft
    return cfg


def _make_connector(mock_helper, **config_overrides):
    """Instantiate connector with mocks, bypassing real client/converter init."""
    cfg = _make_config(**config_overrides)
    conn = UstaProdaftConnector.__new__(UstaProdaftConnector)
    conn.config = cfg
    conn.helper = mock_helper
    conn.work_id = None
    conn.client = MagicMock()
    conn.converter = MagicMock()
    conn.converter.author = MagicMock()
    conn.converter.tlp_marking = MagicMock()
    return conn


# =====================================================================
# State helpers
# =====================================================================

class TestStateHelpers:
    def test_get_state_none(self, mock_helper):
        conn = _make_connector(mock_helper)
        mock_helper.get_state.return_value = None
        assert conn._get_state() == {}

    def test_get_state_existing(self, mock_helper):
        conn = _make_connector(mock_helper)
        mock_helper.get_state.return_value = {"cursor": "abc"}
        assert conn._get_state() == {"cursor": "abc"}

    def test_compute_default_start(self, mock_helper):
        conn = _make_connector(mock_helper)
        result = conn._compute_default_start()
        assert result.endswith("Z")

    def test_get_start_for_feed_with_cursor(self, mock_helper):
        conn = _make_connector(mock_helper)
        assert conn._get_start_for_feed({"k": "2026-01-01T00:00:00Z"}, "k") == "2026-01-01T00:00:00Z"

    def test_get_start_for_feed_without_cursor(self, mock_helper):
        conn = _make_connector(mock_helper)
        result = conn._get_start_for_feed({}, "missing_key")
        assert result.endswith("Z")


# =====================================================================
# Work management
# =====================================================================

class TestWorkManagement:
    def test_initiate_work(self, mock_helper):
        conn = _make_connector(mock_helper)
        wid = conn._initiate_work("test job")
        assert wid == "test-work-id"
        assert conn.work_id == "test-work-id"

    def test_complete_work(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.work_id = "w1"
        conn._complete_work("done")
        mock_helper.api.work.to_processed.assert_called_once_with("w1", "done")
        assert conn.work_id is None

    def test_complete_work_no_work_id(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.work_id = None
        conn._complete_work("done")
        mock_helper.api.work.to_processed.assert_not_called()


# =====================================================================
# Bundle sending
# =====================================================================

class TestSendStixObjects:
    def test_empty_list(self, mock_helper):
        conn = _make_connector(mock_helper)
        assert conn._send_stix_objects([], "w1", "Test") == 0

    def test_single_batch(self, mock_helper):
        conn = _make_connector(mock_helper)
        objs = [MagicMock()] * 10
        sent = conn._send_stix_objects(objs, "w1", "Test")
        assert sent == 10
        mock_helper.send_stix2_bundle.assert_called_once()

    def test_multiple_batches(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.BUNDLE_BATCH_SIZE = 3
        objs = [MagicMock()] * 7
        sent = conn._send_stix_objects(objs, "w1", "Test")
        assert sent == 7
        assert mock_helper.send_stix2_bundle.call_count == 3  # 3+3+1


# =====================================================================
# Per-feed collectors
# =====================================================================

class TestCollectors:
    def _setup_client_pages(self, conn, method_name, pages):
        getattr(conn.client, method_name).return_value = iter(pages)

    def test_collect_malicious_urls(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malicious_url.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_malicious_urls",
                                 [[{"id": "1", "created": "2026-01-01T00:00:00Z"}]])
        objs, last = conn._collect_malicious_urls("2026-01-01T00:00:00Z")
        assert len(objs) == 1
        assert last == "2026-01-01T00:00:00Z"

    def test_collect_malicious_urls_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malicious_url.side_effect = ValueError("bad")
        self._setup_client_pages(conn, "get_malicious_urls",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_malicious_urls("t")
        assert objs == []

    def test_collect_phishing_sites(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_phishing_site.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_phishing_sites",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_phishing_sites("t")
        assert len(objs) == 1

    def test_collect_phishing_sites_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_phishing_site.side_effect = ValueError("bad")
        self._setup_client_pages(conn, "get_phishing_sites",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_phishing_sites("t")
        assert objs == []

    def test_collect_malware_hashes(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malware_hash.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_malware_hashes",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_malware_hashes("t")
        assert len(objs) == 1

    def test_collect_malware_hashes_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malware_hash.side_effect = ValueError("bad")
        self._setup_client_pages(conn, "get_malware_hashes",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_malware_hashes("t")
        assert objs == []

    def test_collect_compromised_credentials(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_compromised_credential.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_compromised_credentials",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_compromised_credentials("t")
        assert len(objs) == 1

    def test_collect_compromised_credentials_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_compromised_credential.side_effect = ValueError("bad")
        self._setup_client_pages(conn, "get_compromised_credentials",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_compromised_credentials("t")
        assert objs == []

    def test_collect_credit_card_tickets(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_credit_card_ticket.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_credit_card_tickets",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_credit_card_tickets("t")
        assert len(objs) == 1

    def test_collect_credit_card_tickets_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_credit_card_ticket.side_effect = ValueError("bad")
        self._setup_client_pages(conn, "get_credit_card_tickets",
                                 [[{"id": "1", "created": "t"}]])
        objs, _ = conn._collect_credit_card_tickets("t")
        assert objs == []

    def test_collect_no_created_field(self, mock_helper):
        """Record without 'created' key → last_created stays None."""
        conn = _make_connector(mock_helper)
        conn.converter.convert_malicious_url.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_malicious_urls", [[{"id": "1"}]])
        _, last = conn._collect_malicious_urls("t")
        assert last is None


# =====================================================================
# process_message — integration-level
# =====================================================================

class TestProcessMessage:
    def test_full_run_all_feeds_with_data(self, mock_helper):
        conn = _make_connector(mock_helper)
        mock_helper.get_state.return_value = None
        # Each collector returns some objects
        for m in ("_collect_malicious_urls", "_collect_phishing_sites",
                  "_collect_malware_hashes", "_collect_compromised_credentials",
                  "_collect_credit_card_tickets"):
            setattr(conn, m, MagicMock(return_value=([MagicMock()], "2026-01-01T00:00:00Z")))
        conn._send_stix_objects = MagicMock(return_value=1)
        conn.process_message()
        assert mock_helper.set_state.called
        state_arg = mock_helper.set_state.call_args[0][0]
        assert state_arg.get("last_run_with_data") is not None

    def test_full_run_no_data(self, mock_helper):
        conn = _make_connector(mock_helper)
        for m in ("_collect_malicious_urls", "_collect_phishing_sites",
                  "_collect_malware_hashes", "_collect_compromised_credentials",
                  "_collect_credit_card_tickets"):
            setattr(conn, m, MagicMock(return_value=([], None)))
        conn.process_message()
        state_arg = mock_helper.set_state.call_args[0][0]
        assert "last_run_with_data" not in state_arg

    def test_feed_disabled(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn.process_message()
        # No collectors should have been called
        conn.client.get_malicious_urls.assert_not_called()

    def test_usta_client_error_caught(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn._collect_malicious_urls = MagicMock(side_effect=UstaClientError("auth"))
        conn.process_message()  # should not raise
        mock_helper.connector_logger.error.assert_called()

    def test_generic_error_caught(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn._collect_malicious_urls = MagicMock(side_effect=RuntimeError("boom"))
        conn.process_message()  # should not raise

    def test_keyboard_interrupt(self, mock_helper):
        conn = _make_connector(mock_helper)
        mock_helper.get_state.side_effect = KeyboardInterrupt()
        with pytest.raises(SystemExit):
            conn.process_message()

    def test_unexpected_outer_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        mock_helper.get_state.side_effect = TypeError("weird")
        conn.process_message()  # logged, not raised
        mock_helper.connector_logger.error.assert_called()

    def test_existing_state_preserved(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        mock_helper.get_state.return_value = {"old_key": "old_val"}
        conn.process_message()
        state_arg = mock_helper.set_state.call_args[0][0]
        assert state_arg["old_key"] == "old_val"

    def test_phishing_client_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn._collect_phishing_sites = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_phishing_generic_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn._collect_phishing_sites = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_hashes_client_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn._collect_malware_hashes = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_hashes_generic_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_compromised_credentials=False,
                               import_credit_cards=False)
        conn._collect_malware_hashes = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_creds_client_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_credit_cards=False)
        conn._collect_compromised_credentials = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_creds_generic_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_credit_cards=False)
        conn._collect_compromised_credentials = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_cards_client_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False)
        conn._collect_credit_card_tickets = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_cards_generic_error(self, mock_helper):
        conn = _make_connector(mock_helper,
                               import_malicious_urls=False,
                               import_phishing_sites=False,
                               import_malware_hashes=False,
                               import_compromised_credentials=False)
        conn._collect_credit_card_tickets = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()


# =====================================================================
# run()
# =====================================================================

class TestRun:
    def test_run_calls_schedule_process(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.run()
        mock_helper.schedule_process.assert_called_once()
