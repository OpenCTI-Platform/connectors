import json
from unittest.mock import MagicMock, patch

import pytest
import requests
from connector.connector import HatchingTriageSandboxConnector, TriageClient
from connectors_sdk.models.enums import TLPLevel
from requests import RequestException
from triage.client import ServerError


@pytest.fixture
def connector(mock_opencti_connector_helper):
    config = MagicMock()
    config.opencti.url = "http://localhost:8080"
    config.hatching_triage_sandbox.base_url = "https://tria.ge/api"
    config.hatching_triage_sandbox.token.get_secret_value.return_value = "fake-token"
    config.hatching_triage_sandbox.use_existing_analysis = True
    config.hatching_triage_sandbox.family_color = "#0059f7"
    config.hatching_triage_sandbox.botnet_color = "#f79e00"
    config.hatching_triage_sandbox.campaign_color = "#7a01e5"
    config.hatching_triage_sandbox.tag_color = "#54483b"
    config.hatching_triage_sandbox.max_attempts = 3
    config.connector.max_tlp = TLPLevel.AMBER

    helper = MagicMock()
    helper.api.identity.create.return_value = {"standard_id": "identity--fake"}

    with patch("connector.connector.TriageClient"):
        instance = HatchingTriageSandboxConnector(config, helper)

    return instance


class TestSearchForAnalysis:
    def test_returns_sample_id_when_reported(self, connector):
        """Should return sample_id when an existing reported analysis is found."""
        connector.triage_client.search.return_value = iter(
            [{"id": "sample-123", "status": "reported"}]
        )

        result = connector._search_for_analysis("url:https://example.com")

        assert result == "sample-123"
        connector.helper.connector_logger.info.assert_called()

    def test_returns_none_when_no_results(self, connector):
        """Should return None when no existing analysis is found."""
        connector.triage_client.search.return_value = iter([])

        result = connector._search_for_analysis("url:https://example.com")

        assert result is None

    def test_returns_none_on_server_error(self, connector):
        """Should return None and log a warning when a ServerError occurs (e.g. 504 timeout)."""
        import json

        mock_response = MagicMock()
        mock_response.status_code = 504
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)

        http_error = MagicMock()
        http_error.response = mock_response

        connector.triage_client.search.return_value = _raise_server_error(http_error)

        result = connector._search_for_analysis("url:https://example.com")

        assert result is None
        connector.helper.connector_logger.warning.assert_called_once()

    def test_returns_none_when_use_existing_analysis_disabled(self, connector):
        """Should return None without searching when use_existing_analysis is False."""
        connector.use_existing_analysis = False

        result = connector._search_for_analysis("url:https://example.com")

        assert result is None
        connector.triage_client.search.assert_not_called()


class TestProcessMessage:
    def test_processes_stix_file_like_an_artifact(self, connector):
        observable = {
            "entity_type": "StixFile",
            "observable_value": "malware.exe",
            "objectMarking": [],
        }
        data = {"enrichment_entity": observable, "stix_objects": []}
        connector._process_observable = MagicMock(return_value="enriched")

        result = connector._process_message(data)

        assert result == "enriched"
        connector._process_observable.assert_called_once_with(observable, "stixfile")

    def test_stixfile_attachments_are_not_fetched_or_submitted(self, connector):
        observable = {
            "entity_type": "StixFile",
            "observable_value": "malware.exe",
            "importFiles": [{"id": "file-id", "name": "malware.exe"}],
            "hashes": [{"algorithm": "SHA-256", "hash": "file-hash"}],
        }
        connector._search_for_analysis = MagicMock(return_value=None)
        connector._submit_sample = MagicMock()

        result = connector._process_file(observable, "stixfile")

        assert result == "No existing Hatching Triage analysis found for malware.exe"
        connector.helper.api.fetch_opencti_file.assert_not_called()
        connector._submit_sample.assert_not_called()
        connector.triage_client.overview_report.assert_not_called()
        connector._search_for_analysis.assert_called_once_with("sha256:file-hash")

    def test_fails_for_stixfile_when_existing_analysis_is_disabled(self, connector):
        connector.use_existing_analysis = False
        observable = {
            "entity_type": "StixFile",
            "observable_value": "file-hash",
            "hashes": [{"algorithm": "SHA-256", "hash": "file-hash"}],
        }
        connector._submit_sample = MagicMock()

        with pytest.raises(ValueError, match="enable use_existing_analysis"):
            connector._process_file(observable, "stixfile")

        connector.helper.api.fetch_opencti_file.assert_not_called()
        connector._submit_sample.assert_not_called()
        connector.triage_client.search.assert_not_called()

    def test_submits_artifact_when_no_existing_analysis_matches(self, connector):
        observable = {
            "entity_type": "Artifact",
            "observable_value": "malware.exe",
            "importFiles": [{"id": "file-id", "name": "malware.exe"}],
        }
        connector.helper.api.fetch_opencti_file.return_value = b"file-content"
        connector._get_sha256 = MagicMock(return_value="file-hash")
        connector._search_for_analysis = MagicMock(return_value=None)
        connector._submit_sample = MagicMock(return_value="sample-123")
        connector.triage_client.overview_report.return_value = {}
        connector._process_overview_report = MagicMock(return_value="enriched")

        result = connector._process_file(observable, "artifact")

        assert result == "enriched"
        connector.helper.api.fetch_opencti_file.assert_called_once_with(
            "http://localhost:8080/storage/get/file-id", True
        )
        connector._submit_sample.assert_called_once_with(
            file_name="malware.exe", file_content=b"file-content"
        )

    def test_reuses_analysis_for_hash_only_stix_file(self, connector):
        observable = {
            "entity_type": "StixFile",
            "observable_value": "file-hash",
            "hashes": [{"algorithm": "SHA-256", "hash": "file-hash"}],
        }
        connector._search_for_analysis = MagicMock(return_value="sample-123")
        connector.triage_client.overview_report.return_value = {}
        connector._process_overview_report = MagicMock(return_value="enriched")

        result = connector._process_file(observable, "stixfile")

        assert result == "enriched"
        connector._search_for_analysis.assert_called_once_with("sha256:file-hash")
        connector._process_overview_report.assert_called_once_with(
            observable, {}, "sample-123", "stixfile"
        )

    def test_raises_for_artifact_without_files(self, connector):
        observable = {
            "entity_type": "Artifact",
            "observable_value": "example.bin",
            "objectMarking": [],
        }

        with pytest.raises(ValueError, match="No files found"):
            connector._process_file(observable, "artifact")

        connector.triage_client.overview_report.assert_not_called()

    @pytest.mark.parametrize(
        "algorithm, expected_query",
        [
            ("SHA-256", "sha256:file-hash"),
            ("SHA-1", "sha1:file-hash"),
            ("MD5", "md5:file-hash"),
            ("SHA-512", "sha512:file-hash"),
        ],
    )
    def test_reuses_analysis_for_hash_only_stix_file_with_supported_hashes(
        self, connector, algorithm, expected_query
    ):
        observable = {
            "entity_type": "StixFile",
            "observable_value": "file-hash",
            "hashes": [{"algorithm": algorithm, "hash": "file-hash"}],
        }
        connector._search_for_analysis = MagicMock(return_value="sample-123")
        connector.triage_client.overview_report.return_value = {}
        connector._process_overview_report = MagicMock(return_value="enriched")

        result = connector._process_file(observable, "stixfile")

        assert result == "enriched"
        connector._search_for_analysis.assert_called_once_with(expected_query)
        connector._process_overview_report.assert_called_once_with(
            observable, {}, "sample-123", "stixfile"
        )

    def test_reuses_analysis_for_hash_only_stix_file_with_multiple_hashes(
        self, connector
    ):
        observable = {
            "entity_type": "StixFile",
            "observable_value": "file-hash",
            "hashes": [
                {"algorithm": "SHA-256", "hash": "wrong-hash"},
                {"algorithm": "SHA-1", "hash": "file-hash"},
                {"algorithm": "MD5", "hash": "other-wrong-hash"},
            ],
        }
        connector._search_for_analysis = MagicMock(side_effect=[None, "sample-123"])
        connector.triage_client.overview_report.return_value = {}
        connector._process_overview_report = MagicMock(return_value="enriched")

        result = connector._process_file(observable, "stixfile")

        assert result == "enriched"
        assert connector._search_for_analysis.call_count == 2
        connector._search_for_analysis.assert_any_call("sha256:wrong-hash")
        connector._search_for_analysis.assert_any_call("sha1:file-hash")
        connector._process_overview_report.assert_called_once_with(
            observable, {}, "sample-123", "stixfile"
        )


def _raise_server_error(http_error):
    """Generator that raises a ServerError when iterated."""
    raise ServerError(http_error)
    yield  # noqa: unreachable - makes this a generator


class TestBuildReportUrl:
    @pytest.mark.parametrize(
        "base_url, expected",
        [
            ("https://tria.ge/api", "https://tria.ge/sample-123/"),
            ("https://tria.ge/api/", "https://tria.ge/sample-123/"),
            ("https://private.tria.ge/api", "https://private.tria.ge/sample-123/"),
            (
                "https://sandbox.recordedfuture.com/api",
                "https://sandbox.recordedfuture.com/sample-123/",
            ),
            (
                "https://us-sandbox.recordedfuture.com/api",
                "https://us-sandbox.recordedfuture.com/sample-123/",
            ),
            (
                "https://user:secret@private.tria.ge/api",
                "https://private.tria.ge/sample-123/",
            ),
            ("https://triage.local:8443/api", "https://triage.local:8443/sample-123/"),
            (
                "https://[2001:db8::1]:8443/api",
                "https://[2001:db8::1]:8443/sample-123/",
            ),
        ],
    )
    def test_report_url_uses_the_configured_host(self, connector, base_url, expected):
        """The analysis link should point to the host of the configured API base URL."""
        connector.base_url = base_url

        assert connector._build_report_url("sample-123") == expected


def _server_error(status_code):
    http_error = MagicMock()
    http_error.response.status_code = status_code
    http_error.response.json.return_value = {}
    return ServerError(http_error)


def _html_response(status_code):
    response = requests.Response()
    response.status_code = status_code
    response._content = b"<html><h1>Bad Gateway</h1></html>"
    return response


def _http_error(status_code):
    return requests.HTTPError(response=_html_response(status_code))


@patch("connector.connector.time.sleep")
class TestRetries:
    def test_overview_report_retries_on_server_error(self, mock_sleep, connector):
        connector.triage_client.overview_report.side_effect = [
            _server_error(502),
            {"analysis": {}},
        ]

        result = connector._get_overview_report("sample-123")

        assert result == {"analysis": {}}
        assert connector.triage_client.overview_report.call_count == 2
        mock_sleep.assert_called_once()

    def test_overview_report_raises_after_max_attempts(self, mock_sleep, connector):
        connector.triage_client.overview_report.side_effect = _server_error(502)

        with pytest.raises(ServerError):
            connector._get_overview_report("sample-123")

        assert connector.triage_client.overview_report.call_count == 3

    def test_overview_report_does_not_retry_client_error(self, mock_sleep, connector):
        connector.triage_client.overview_report.side_effect = _server_error(404)

        with pytest.raises(ServerError):
            connector._get_overview_report("sample-123")

        assert connector.triage_client.overview_report.call_count == 1
        mock_sleep.assert_not_called()

    def test_overview_report_retries_on_html_bad_gateway(self, mock_sleep, connector):
        response = requests.Response()
        response.status_code = 502
        response._content = b"<html><body><h1>502 Bad Gateway</h1></body></html>"
        calls = iter([requests.HTTPError(response=response), None])

        def overview_report(_sample_id):
            http_error = next(calls)
            if http_error is None:
                return {"analysis": {}}
            raise ServerError(http_error)

        connector.triage_client.overview_report.side_effect = overview_report

        result = connector._get_overview_report("sample-123")

        assert result == {"analysis": {}}
        mock_sleep.assert_called_once()

    def test_overview_report_retries_on_connection_error(self, mock_sleep, connector):
        connector.triage_client.overview_report.side_effect = [
            requests.ConnectionError("connection dropped"),
            {"analysis": {}},
        ]

        result = connector._get_overview_report("sample-123")

        assert result == {"analysis": {}}
        assert connector.triage_client.overview_report.call_count == 2

    def test_task_file_retries_until_available(self, mock_sleep, connector):
        connector.triage_client.sample_task_file.side_effect = [
            b'{"error":"NOT_AVAILABLE"}',
            b'{"error":"NOT_AVAILABLE"}',
            b"file-content",
        ]

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result == b"file-content"
        assert connector.triage_client.sample_task_file.call_count == 3

    def test_task_file_returns_none_after_max_attempts(self, mock_sleep, connector):
        connector.triage_client.sample_task_file.return_value = (
            b'{"error":"NOT_AVAILABLE"}'
        )

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result is None
        assert connector.triage_client.sample_task_file.call_count == 3
        assert mock_sleep.call_count == 2

    def test_task_file_retries_on_any_triage_error_body(self, mock_sleep, connector):
        connector.triage_client.sample_task_file.side_effect = [
            b'{"error": "BAD_GATEWAY", "message": "upstream timeout"}',
            b"file-content",
        ]

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result == b"file-content"
        assert connector.triage_client.sample_task_file.call_count == 2

    @pytest.mark.parametrize(
        "content",
        [
            b'{"error": "x", "data": [1, 2]}',
            b'{"config": {"c2": "1.2.3.4"}}',
            b"<html><body>dropped phishing page</body></html>",
            b"{" + b" " * 5000 + b'"error": "x"}',
            b"{\xff not json",
        ],
    )
    def test_task_file_keeps_real_file_content(self, mock_sleep, connector, content):
        connector.triage_client.sample_task_file.return_value = content

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result == content
        mock_sleep.assert_not_called()

    def test_task_file_retries_on_bad_gateway(self, mock_sleep, connector):
        connector.triage_client.sample_task_file.side_effect = [
            _http_error(502),
            b"file-content",
        ]

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result == b"file-content"
        assert connector.triage_client.sample_task_file.call_count == 2
        mock_sleep.assert_called_once()

    def test_task_file_returns_none_after_max_attempts_on_server_error(
        self, mock_sleep, connector
    ):
        connector.triage_client.sample_task_file.side_effect = _http_error(502)

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result is None
        assert connector.triage_client.sample_task_file.call_count == 3
        assert mock_sleep.call_count == 2

    def test_task_file_skips_without_retry_on_client_error(self, mock_sleep, connector):
        connector.triage_client.sample_task_file.side_effect = _http_error(404)

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result is None
        assert connector.triage_client.sample_task_file.call_count == 1
        mock_sleep.assert_not_called()

    def test_task_file_retries_on_connection_error(self, mock_sleep, connector):
        connector.triage_client.sample_task_file.side_effect = [
            requests.ConnectionError("connection dropped"),
            b"file-content",
        ]

        result = connector._get_task_file("sample-123", "task-1", "file.bin")

        assert result == b"file-content"
        assert connector.triage_client.sample_task_file.call_count == 2

    def test_wait_for_analysis_retries_on_invalid_json(self, mock_sleep, connector):
        connector.triage_client.sample_events.side_effect = [
            _raise_json_error(),
            iter([{"status": "pending"}, {"status": "reported"}]),
        ]

        connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 2
        mock_sleep.assert_called_once()

    def test_wait_for_analysis_retries_on_connection_error(self, mock_sleep, connector):
        connector.triage_client.sample_events.side_effect = [
            RequestException("connection reset"),
            iter([{"status": "reported"}]),
        ]

        connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 2

    def test_wait_for_analysis_retries_on_event_without_status(
        self, mock_sleep, connector
    ):
        connector.triage_client.sample_events.side_effect = [
            iter([{"error": "BAD_GATEWAY", "message": "upstream timeout"}]),
            iter([{"status": "pending"}, {"status": "reported"}]),
        ]

        connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 2
        mock_sleep.assert_called_once()

    def test_wait_for_analysis_retries_on_server_error(self, mock_sleep, connector):
        connector.triage_client.sample_events.side_effect = [
            _server_error(503),
            iter([{"status": "reported"}]),
        ]

        connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 2
        mock_sleep.assert_called_once()

    def test_wait_for_analysis_does_not_retry_client_error(self, mock_sleep, connector):
        connector.triage_client.sample_events.side_effect = _server_error(404)

        with pytest.raises(ServerError):
            connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 1
        mock_sleep.assert_not_called()

    def test_wait_for_analysis_raises_when_stream_never_reports(
        self, mock_sleep, connector
    ):
        connector.triage_client.sample_events.side_effect = lambda _: iter(
            [{"status": "pending"}]
        )

        with pytest.raises(ValueError, match="did not finish after 3 attempts"):
            connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 3

    def test_wait_for_analysis_does_not_retry_failed_analysis(
        self, mock_sleep, connector
    ):
        connector.triage_client.sample_events.return_value = iter(
            [{"status": "failed"}]
        )

        with pytest.raises(ValueError, match="Analysis sample-123 failed"):
            connector._wait_for_analysis("sample-123")

        assert connector.triage_client.sample_events.call_count == 1
        mock_sleep.assert_not_called()


class TestTriageClient:
    @pytest.mark.parametrize("status_code", [404, 502])
    def test_file_download_raises_on_http_error(self, status_code):
        response = _html_response(status_code)

        with patch("connector.connector.Session") as session_cls:
            session = session_cls.return_value.__enter__.return_value
            session.merge_environment_settings.return_value = {}
            session.send.return_value = response

            with pytest.raises(requests.HTTPError):
                TriageClient("token", root_url="https://tria.ge/api").sample_task_file(
                    "sample-123", "task-1", "file.bin"
                )

    def test_file_download_returns_content_on_success(self):
        response = requests.Response()
        response.status_code = 200
        response._content = b"file-content"

        with patch("connector.connector.Session") as session_cls:
            session = session_cls.return_value.__enter__.return_value
            session.merge_environment_settings.return_value = {}
            session.send.return_value = response

            result = TriageClient(
                "token", root_url="https://tria.ge/api"
            ).sample_task_file("sample-123", "task-1", "file.bin")

        assert result == b"file-content"


def _raise_json_error():
    raise json.JSONDecodeError("Expecting value", "<html>", 0)
    yield  # noqa: unreachable - makes this a generator


class TestSendBundle:
    def test_sends_bundle_without_cleanup_of_inconsistent_objects(self, connector):
        connector.helper.stix2_create_bundle.return_value = "bundle"
        connector.helper.send_stix2_bundle.return_value = ["bundle"]

        result = connector._send_bundle(["stix-object"])

        connector.helper.stix2_create_bundle.assert_called_once_with(["stix-object"])
        connector.helper.send_stix2_bundle.assert_called_once_with("bundle")
        assert result == "Sent 1 stix bundle(s) for worker import"


class TestExtractedFileDownload:
    OBSERVABLE = {
        "id": "observable-id",
        "standard_id": "artifact--4cb2c4c1-7a3c-4e2b-9a8e-3c6f7f1b2d10",
    }
    OVERVIEW = {
        "analysis": {},
        "extracted": [
            {
                "config": {"rule": "Agenttesla", "c2": [], "credentials": []},
                "tasks": ["behavioral1"],
                "dumped_file": "memory/file.bin",
            }
        ],
    }

    @pytest.fixture(autouse=True)
    def _setup(self, connector):
        connector.identity = "identity--7b0e9c3a-5d1f-4c8e-8f2a-1e6d3b9c4a70"
        connector._send_bundle = MagicMock(return_value="sent")

    def test_skips_extracted_file_when_not_available(self, connector):
        connector._get_task_file = MagicMock(return_value=None)

        connector._process_overview_report(
            self.OBSERVABLE, self.OVERVIEW, "sample-123", "artifact"
        )

        connector._get_task_file.assert_called_once_with(
            "sample-123", "behavioral1", "memory/file.bin"
        )
        connector.helper.api.stix_cyber_observable.upload_artifact.assert_not_called()
        connector.helper.connector_logger.warning.assert_called_once()

    @patch("connector.connector.magic.from_buffer", return_value="text/plain")
    def test_uploads_extracted_file_when_available(self, _mock_magic, connector):
        connector._get_task_file = MagicMock(return_value=b"file-content")
        upload = connector.helper.api.stix_cyber_observable.upload_artifact
        upload.return_value = {
            "id": "artifact-id",
            "standard_id": "artifact--9d1e2f3a-4b5c-4d6e-8f7a-0b1c2d3e4f50",
        }

        connector._process_overview_report(
            self.OBSERVABLE, self.OVERVIEW, "sample-123", "artifact"
        )

        upload.assert_called_once()
        assert upload.call_args.kwargs["data"] == b"file-content"
        assert upload.call_args.kwargs["file_name"] == "sample-123_memory/file.bin"
