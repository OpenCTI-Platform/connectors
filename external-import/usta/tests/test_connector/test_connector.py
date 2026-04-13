"""Unit tests for the USTA connector orchestrator — 100 % coverage."""

# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from connector.connector import UstaConnector
from usta_client import UstaClientError

# ---- Helpers ----


def _make_config(**overrides):
    """Build a minimal mock ConnectorSettings."""
    cfg = MagicMock()
    cfg.connector.name = "USTA Test"
    cfg.connector.duration_period = timedelta(hours=1)
    usta_cfg = MagicMock()
    usta_cfg.api_base_url = "https://usta.prodaft.com"
    usta_cfg.api_key = "key"
    usta_cfg.page_size = 10
    usta_cfg.tlp_level = "amber"
    usta_cfg.confidence_level = 80
    usta_cfg.import_start_date = timedelta(days=7)
    usta_cfg.import_malicious_urls = True
    usta_cfg.import_phishing_sites = True
    usta_cfg.import_malware_hashes = True
    usta_cfg.import_compromised_credentials = True
    usta_cfg.import_credit_cards = True
    usta_cfg.import_deep_sight_tickets = True
    for k, v in overrides.items():
        setattr(usta_cfg, k, v)
    cfg.usta = usta_cfg
    return cfg


def _make_connector(mock_helper, **config_overrides):
    """Instantiate connector with mocks, bypassing real client/converter init."""
    cfg = _make_config(**config_overrides)
    conn = UstaConnector.__new__(UstaConnector)
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
        assert (
            conn._get_start_for_feed({"k": "2026-01-01T00:00:00Z"}, "k")
            == "2026-01-01T00:00:00Z"
        )

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
        mock_helper.api.work.to_processed.assert_called_once_with(
            "w1", "done", in_error=False
        )
        assert conn.work_id is None

    def test_complete_work_in_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.work_id = "w1"
        conn._complete_work("failed", in_error=True)
        mock_helper.api.work.to_processed.assert_called_once_with(
            "w1", "failed", in_error=True
        )
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
        self._setup_client_pages(
            conn,
            "get_malicious_urls",
            [[{"id": "1", "created": "2026-01-01T00:00:00Z"}]],
        )
        objs, last = conn._collect_malicious_urls("2026-01-01T00:00:00Z")
        assert len(objs) == 1
        assert last == "2026-01-01T00:00:00Z"

    def test_collect_malicious_urls_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malicious_url.side_effect = ValueError("bad")
        self._setup_client_pages(
            conn, "get_malicious_urls", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_malicious_urls("t")
        assert objs == []

    def test_collect_phishing_sites(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_phishing_site.return_value = [MagicMock()]
        self._setup_client_pages(
            conn, "get_phishing_sites", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_phishing_sites("t")
        assert len(objs) == 1

    def test_collect_phishing_sites_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_phishing_site.side_effect = ValueError("bad")
        self._setup_client_pages(
            conn, "get_phishing_sites", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_phishing_sites("t")
        assert objs == []

    def test_collect_malware_hashes(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malware_hash.return_value = [MagicMock()]
        self._setup_client_pages(
            conn, "get_malware_hashes", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_malware_hashes("t")
        assert len(objs) == 1

    def test_collect_malware_hashes_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_malware_hash.side_effect = ValueError("bad")
        self._setup_client_pages(
            conn, "get_malware_hashes", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_malware_hashes("t")
        assert objs == []

    def test_collect_compromised_credentials(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_compromised_credential.return_value = [MagicMock()]
        self._setup_client_pages(
            conn, "get_compromised_credentials", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_compromised_credentials("t")
        assert len(objs) == 1

    def test_collect_compromised_credentials_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_compromised_credential.side_effect = ValueError("bad")
        self._setup_client_pages(
            conn, "get_compromised_credentials", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_compromised_credentials("t")
        assert objs == []

    def test_collect_credit_card_tickets(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_credit_card_ticket.return_value = [MagicMock()]
        self._setup_client_pages(
            conn, "get_credit_card_tickets", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_credit_card_tickets("t")
        assert len(objs) == 1

    def test_collect_credit_card_tickets_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_credit_card_ticket.side_effect = ValueError("bad")
        self._setup_client_pages(
            conn, "get_credit_card_tickets", [[{"id": "1", "created": "t"}]]
        )
        objs, _ = conn._collect_credit_card_tickets("t")
        assert objs == []

    def test_collect_no_created_field(self, mock_helper):
        """Record without 'created' key → last_created stays None."""
        conn = _make_connector(mock_helper)
        conn.converter.convert_malicious_url.return_value = [MagicMock()]
        self._setup_client_pages(conn, "get_malicious_urls", [[{"id": "1"}]])
        _, last = conn._collect_malicious_urls("t")
        assert last is None

    def test_collect_deep_sight_tickets(self, mock_helper):
        conn = _make_connector(mock_helper)
        report_obj = MagicMock()
        report_obj.id = "report--test-id"
        report_obj.type = "report"
        conn.converter.convert_deep_sight_ticket.return_value = [report_obj]
        self._setup_client_pages(
            conn,
            "get_deep_sight_tickets",
            [
                [
                    {
                        "id": 1,
                        "created": "2026-03-01T00:00:00Z",
                        "content": {"report": None},
                    }
                ]
            ],
        )
        objs, last = conn._collect_deep_sight_tickets("2026-01-01T00:00:00Z")
        assert len(objs) == 1
        assert last == "2026-03-01T00:00:00Z"

    def test_collect_deep_sight_tickets_downloads_pdf_inline(self, mock_helper):
        """When a record has a report URL, the PDF is downloaded and embedded in the record
        before conversion so that convert_deep_sight_ticket receives _pdf_data/_pdf_filename.
        """
        from unittest.mock import patch

        conn = _make_connector(mock_helper)
        report_obj = MagicMock()
        report_obj.id = "report--abc"
        report_obj.type = "report"
        conn.converter.convert_deep_sight_ticket.return_value = [report_obj]
        url = "https://cdn.example.com/attachments/Report_test.pdf?AWSKey=x&Expires=999"
        self._setup_client_pages(
            conn,
            "get_deep_sight_tickets",
            [
                [
                    {
                        "id": 1,
                        "created": "2026-03-01T00:00:00Z",
                        "content": {"report": url},
                    }
                ]
            ],
        )
        with patch("connector.connector.requests") as mock_requests:
            mock_resp = MagicMock()
            mock_resp.iter_content.return_value = [b"%PDF-1.4 test"]
            mock_resp.raise_for_status = MagicMock()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_requests.get.return_value = mock_resp
            conn._collect_deep_sight_tickets("t")
        # The converter must have been called with _pdf_data/_pdf_filename injected
        call_record = conn.converter.convert_deep_sight_ticket.call_args[0][0]
        assert call_record.get("_pdf_data") == b"%PDF-1.4 test"
        assert call_record.get("_pdf_filename", "").endswith(".pdf")

    def test_collect_deep_sight_tickets_pdf_download_failure_continues(
        self, mock_helper
    ):
        """A PDF download failure logs a warning but does not abort record conversion."""
        from unittest.mock import patch

        conn = _make_connector(mock_helper)
        report_obj = MagicMock()
        report_obj.id = "report--abc"
        report_obj.type = "report"
        conn.converter.convert_deep_sight_ticket.return_value = [report_obj]
        url = "https://cdn.example.com/attachments/Report_expired.pdf"
        self._setup_client_pages(
            conn,
            "get_deep_sight_tickets",
            [
                [
                    {
                        "id": 1,
                        "created": "2026-03-01T00:00:00Z",
                        "content": {"report": url},
                    }
                ]
            ],
        )
        with patch("connector.connector.requests") as mock_requests:
            mock_requests.get.side_effect = Exception("connection timeout")
            objs, _ = conn._collect_deep_sight_tickets("t")
        # Record still converted — just without _pdf_data
        assert len(objs) == 1
        mock_helper.connector_logger.warning.assert_called()

    def test_collect_deep_sight_tickets_convert_error(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.converter.convert_deep_sight_ticket.side_effect = ValueError("bad")
        self._setup_client_pages(
            conn, "get_deep_sight_tickets", [[{"id": 1, "created": "t", "content": {}}]]
        )
        objs, _ = conn._collect_deep_sight_tickets("t")
        assert objs == []


# =====================================================================
# process_message — integration-level
# =====================================================================


class TestProcessMessage:
    def test_full_run_all_feeds_with_data(self, mock_helper):
        conn = _make_connector(mock_helper)
        mock_helper.get_state.return_value = None
        # Each collector returns some objects
        for m in (
            "_collect_malicious_urls",
            "_collect_phishing_sites",
            "_collect_malware_hashes",
            "_collect_compromised_credentials",
            "_collect_credit_card_tickets",
            "_collect_deep_sight_tickets",
        ):
            setattr(
                conn, m, MagicMock(return_value=([MagicMock()], "2026-01-01T00:00:00Z"))
            )
        conn._send_stix_objects = MagicMock(return_value=1)
        conn.process_message()
        assert mock_helper.set_state.called
        state_arg = mock_helper.set_state.call_args[0][0]
        assert state_arg.get("last_run_with_data") is not None

    def test_full_run_no_data(self, mock_helper):
        conn = _make_connector(mock_helper)
        for m in (
            "_collect_malicious_urls",
            "_collect_phishing_sites",
            "_collect_malware_hashes",
            "_collect_compromised_credentials",
            "_collect_credit_card_tickets",
            "_collect_deep_sight_tickets",
        ):
            setattr(conn, m, MagicMock(return_value=([], None)))
        conn.process_message()
        state_arg = mock_helper.set_state.call_args[0][0]
        assert "last_run_with_data" not in state_arg

    def test_feed_disabled(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
            import_deep_sight_tickets=False,
        )
        conn.process_message()
        # No collectors should have been called
        conn.client.get_malicious_urls.assert_not_called()

    def test_usta_client_error_caught(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_malicious_urls = MagicMock(side_effect=UstaClientError("auth"))
        conn.process_message()  # should not raise
        mock_helper.connector_logger.error.assert_called()

    def test_generic_error_caught(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
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
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        mock_helper.get_state.return_value = {"old_key": "old_val"}
        conn.process_message()
        state_arg = mock_helper.set_state.call_args[0][0]
        assert state_arg["old_key"] == "old_val"

    def test_phishing_client_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_phishing_sites = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_phishing_generic_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_phishing_sites = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_hashes_client_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_malware_hashes = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_hashes_generic_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_malware_hashes = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_creds_client_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_credit_cards=False,
        )
        conn._collect_compromised_credentials = MagicMock(
            side_effect=UstaClientError("x")
        )
        conn.process_message()

    def test_creds_generic_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_credit_cards=False,
        )
        conn._collect_compromised_credentials = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_cards_client_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
        )
        conn._collect_credit_card_tickets = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_cards_generic_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
        )
        conn._collect_credit_card_tickets = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()

    def test_deep_sight_client_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_deep_sight_tickets = MagicMock(side_effect=UstaClientError("x"))
        conn.process_message()

    def test_deep_sight_generic_error(self, mock_helper):
        conn = _make_connector(
            mock_helper,
            import_malicious_urls=False,
            import_phishing_sites=False,
            import_malware_hashes=False,
            import_compromised_credentials=False,
            import_credit_cards=False,
        )
        conn._collect_deep_sight_tickets = MagicMock(side_effect=RuntimeError("x"))
        conn.process_message()


# =====================================================================
# _extract_filename_from_url
# =====================================================================


class TestExtractFilenameFromUrl:
    def test_standard_cdn_url(self):
        url = "https://cdn.example.com/attachments/Report_test.pdf?AWSKey=x&Expires=999"
        assert UstaConnector._extract_filename_from_url(url) == "Report_test.pdf"

    def test_url_encoded_filename(self):
        url = "https://cdn.example.com/attachments/TR_Rapor%20Final.pdf?foo=bar"
        assert UstaConnector._extract_filename_from_url(url) == "TR_Rapor Final.pdf"

    def test_no_pdf_extension_appended(self):
        url = "https://cdn.example.com/attachments/somefile"
        result = UstaConnector._extract_filename_from_url(url)
        assert result.endswith(".pdf")

    def test_empty_path(self):
        url = "https://cdn.example.com/"
        result = UstaConnector._extract_filename_from_url(url)
        assert result.endswith(".pdf")


# =====================================================================
# run()
# =====================================================================


class TestRun:
    def test_run_calls_schedule_process(self, mock_helper):
        conn = _make_connector(mock_helper)
        conn.run()
        mock_helper.schedule_process.assert_called_once()
