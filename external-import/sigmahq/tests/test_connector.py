"""Tests for SigmaHQConnector.process_message — patch coverage.

Covers the orchestration logic in ``connector.py``:
- GitHub metadata unavailable (None or missing ``tag``)
- Empty bundle (no matching asset / all rules failed)
- Happy path (new version → send bundle → update state)
- Same version already ingested → skip
- Unhandled exception after work_id is created → mark in_error
- Failure to mark work as in_error (best-effort close)
"""

from unittest.mock import MagicMock

from connector.connector import SigmaHQConnector


def _make_connector() -> SigmaHQConnector:
    """Build a ``SigmaHQConnector`` with all heavy collaborators mocked."""
    connector = SigmaHQConnector.__new__(SigmaHQConnector)
    connector.config = MagicMock()
    connector.config.sigmahq.rule_package = "sigma_core"
    connector.config.connector.duration_period.total_seconds.return_value = 86400
    connector.helper = MagicMock()
    connector.helper.connect_name = "SigmaHQ"
    connector.helper.connect_id = "test-id"
    connector.helper.api.work.initiate_work.return_value = "work-123"
    connector.client = MagicMock()
    connector.converter_to_stix = MagicMock()
    connector.converter_to_stix.reset_dedup_state = MagicMock()
    connector.converter_to_stix.convert_sigma_rule.return_value = []
    connector.converter_to_stix.author = MagicMock()
    connector.converter_to_stix.tlp_marking = MagicMock()
    return connector


class TestProcessMessageNoReleaseMetadata:
    """When GitHub is unreachable the work is marked as in_error."""

    def test_none_release_metadata_marks_work_in_error(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        connector.client.get_latest_published_version.return_value = None

        connector.process_message()

        connector.helper.api.work.to_processed.assert_called_once()
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert kwargs.get("in_error") is True

    def test_release_without_tag_marks_work_in_error(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        connector.client.get_latest_published_version.return_value = {"assets": []}

        connector.process_message()

        connector.helper.api.work.to_processed.assert_called_once()
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert kwargs.get("in_error") is True


class TestProcessMessageEmptyBundle:
    """When _collect_intelligence returns [] work completes without send."""

    def test_empty_stix_objects_does_not_send_bundle(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        connector.client.get_latest_published_version.return_value = {
            "tag": "r2026-01-01",
            "assets": [
                {
                    "name": "sigma_core.zip",
                    "browser_download_url": "https://example.invalid/sigma_core.zip",
                }
            ],
        }
        connector.client.download_and_convert_package.return_value = []

        connector.process_message()

        connector.helper.send_stix2_bundle.assert_not_called()
        connector.helper.api.work.to_processed.assert_called_once()
        # State is NOT updated when no rules are published.
        connector.helper.set_state.assert_not_called()


class TestProcessMessageHappyPath:
    """Successful run sends the bundle and updates state."""

    def test_new_version_sends_bundle_and_updates_state(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        connector.client.get_latest_published_version.return_value = {
            "tag": "r2026-01-01",
            "assets": [
                {
                    "name": "sigma_core.zip",
                    "browser_download_url": "https://example.invalid/sigma_core.zip",
                }
            ],
        }
        fake_rule = {"filename": "rule.yml", "rule_content": "title: X\n"}
        connector.client.download_and_convert_package.return_value = [fake_rule]
        # Simulate convert returning at least one STIX object
        fake_stix = MagicMock()
        connector.converter_to_stix.convert_sigma_rule.return_value = [fake_stix]
        connector.helper.stix2_create_bundle.return_value = "bundle-json"
        connector.helper.send_stix2_bundle.return_value = ["b1"]

        connector.process_message()

        connector.helper.send_stix2_bundle.assert_called_once()
        connector.helper.set_state.assert_called_once()
        state_arg = connector.helper.set_state.call_args[0][0]
        assert state_arg["rule_package_version"] == "r2026-01-01"

    def test_existing_state_is_preserved_on_update(self):
        """Pre-existing state keys are kept alongside the new version."""
        connector = _make_connector()
        connector.helper.get_state.return_value = {"custom_key": "value"}
        connector.client.get_latest_published_version.return_value = {
            "tag": "r2026-02-01",
            "assets": [
                {
                    "name": "sigma_core.zip",
                    "browser_download_url": "https://example.invalid/sigma_core.zip",
                }
            ],
        }
        fake_rule = {"filename": "rule.yml", "rule_content": "title: Y\n"}
        connector.client.download_and_convert_package.return_value = [fake_rule]
        fake_stix = MagicMock()
        connector.converter_to_stix.convert_sigma_rule.return_value = [fake_stix]
        connector.helper.stix2_create_bundle.return_value = "bundle-json"
        connector.helper.send_stix2_bundle.return_value = ["b1"]

        connector.process_message()

        state_arg = connector.helper.set_state.call_args[0][0]
        assert state_arg["custom_key"] == "value"
        assert state_arg["rule_package_version"] == "r2026-02-01"


class TestProcessMessageSameVersion:
    """When the latest version is already ingested, nothing is sent."""

    def test_same_version_does_not_send_bundle(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = {
            "rule_package_version": "r2026-01-01"
        }
        connector.client.get_latest_published_version.return_value = {
            "tag": "r2026-01-01",
            "assets": [],
        }

        connector.process_message()

        connector.helper.send_stix2_bundle.assert_not_called()
        connector.helper.set_state.assert_not_called()
        # Work is still finalised successfully.
        connector.helper.api.work.to_processed.assert_called_once()
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert kwargs.get("in_error") is None or kwargs.get("in_error") is False


class TestProcessMessageExceptionHandling:
    """Unhandled exceptions mark the work as in_error."""

    def test_exception_after_work_init_marks_in_error(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        # Crash AFTER work_id is assigned (initiate_work returns "work-123").
        connector.client.get_latest_published_version.side_effect = RuntimeError(
            "unexpected"
        )

        connector.process_message()

        connector.helper.api.work.to_processed.assert_called_once()
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert kwargs.get("in_error") is True

    def test_exception_before_work_init_does_not_call_to_processed(self):
        """If the crash is before initiate_work, work_id is None → no close."""
        connector = _make_connector()
        # Make get_state crash — that's called BEFORE initiate_work.
        connector.helper.get_state.side_effect = RuntimeError("early crash")

        connector.process_message()

        # to_processed is never called because work_id is still None.
        connector.helper.api.work.to_processed.assert_not_called()

    def test_failure_to_close_work_is_logged(self):
        """Best-effort close: if to_processed itself raises, we just log."""
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        connector.client.get_latest_published_version.side_effect = RuntimeError("boom")
        connector.helper.api.work.to_processed.side_effect = RuntimeError(
            "platform down"
        )

        # Should NOT raise — the inner except swallows the close failure.
        connector.process_message()

        # The error logger is called at least twice: once for the original
        # exception, once for the failed close attempt.
        assert connector.helper.connector_logger.error.call_count >= 2


class TestProcessMessageConvertError:
    """A single rule conversion failure does not crash the run."""

    def test_rule_conversion_exception_is_logged_and_skipped(self):
        connector = _make_connector()
        connector.helper.get_state.return_value = None
        connector.client.get_latest_published_version.return_value = {
            "tag": "r2026-03-01",
            "assets": [
                {
                    "name": "sigma_core.zip",
                    "browser_download_url": "https://example.invalid/sigma_core.zip",
                }
            ],
        }
        good_rule = {"filename": "good.yml", "rule_content": "title: Good\n"}
        bad_rule = {"filename": "bad.yml", "rule_content": "title: Bad\n"}
        connector.client.download_and_convert_package.return_value = [
            bad_rule,
            good_rule,
        ]
        # First call raises, second returns a valid STIX object.
        fake_stix = MagicMock()
        connector.converter_to_stix.convert_sigma_rule.side_effect = [
            ValueError("parse error"),
            [fake_stix],
        ]
        connector.helper.stix2_create_bundle.return_value = "bundle"
        connector.helper.send_stix2_bundle.return_value = ["b1"]

        connector.process_message()

        # The bad rule is logged as an error but doesn't stop the run.
        connector.helper.connector_logger.error.assert_called()
        # The good rule's bundle is still sent.
        connector.helper.send_stix2_bundle.assert_called_once()


class TestRun:
    """Smoke test for the ``run()`` method wiring."""

    def test_run_calls_schedule_process(self):
        connector = _make_connector()
        connector.run()
        connector.helper.schedule_process.assert_called_once()
        call_kwargs = connector.helper.schedule_process.call_args[1]
        assert call_kwargs["message_callback"] == connector.process_message
        assert call_kwargs["duration_period"] == 86400
