"""Tests for the report PDF download feature (issue #5178).

Covers:
- GTIReportConfig.report_download_pdf config field
- ClientAPIReport.download_report_pdf() method
- ClientAPI.download_report_pdf() delegation
- OrchestratorReport._attach_report_pdf() method
"""

import base64
import logging
from datetime import timedelta
from os import environ as os_environ
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from connector.src.custom.client_api.client_api import ClientAPI
from connector.src.custom.client_api.report.client_api_report import ClientAPIReport
from connector.src.custom.configs.report.gti_config_report import GTIReportConfig
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)
from pydantic import HttpUrl
from pydantic.types import SecretStr

from tests.conftest import mock_env_vars

# =====================
# Fixtures
# =====================


class DummyConfig:
    """Minimal config for testing report PDF download."""

    def __init__(self, report_download_pdf: bool = False):
        self.api_key = SecretStr("fake-key")
        self.api_url = HttpUrl("https://fake-gti.api")
        self.report_import_start_date = timedelta(days=1)
        self.import_reports = True
        self.import_threat_actors = False
        self.import_malware_families = False
        self.import_vulnerabilities = False
        self.import_campaigns = False
        self.import_indicators = False
        self.report_types = ["All"]
        self.report_origins = ["All"]
        self.report_download_pdf = report_download_pdf
        self.tlp_level = "white"
        self.threat_actor_import_start_date = timedelta(days=1)
        self.malware_family_import_start_date = timedelta(days=1)
        self.vulnerability_import_start_date = timedelta(days=1)
        self.campaign_import_start_date = timedelta(days=1)
        self.threat_actor_origins = "All"
        self.malware_family_origins = "All"
        self.vulnerability_origins = "All"
        self.vulnerability_get_related_softwares = True
        self.import_software_toolkits = False
        self.software_toolkit_import_start_date = timedelta(days=1)


@pytest.fixture
def dummy_config():
    return DummyConfig(report_download_pdf=False)


@pytest.fixture
def dummy_config_with_pdf():
    return DummyConfig(report_download_pdf=True)


@pytest.fixture
def logger():
    return logging.getLogger("test_pdf_download")


# =====================
# Config Tests
# =====================


class TestReportDownloadPdfConfig:
    """Tests for the report_download_pdf config field."""

    def test_default_value_is_false(self):
        """report_download_pdf should default to False."""
        env = mock_env_vars(
            os_environ,
            {"GTI_API_KEY": "fake-key"},
        )
        config = GTIReportConfig()
        assert config.report_download_pdf is False  # noqa: S101
        env.stop()

    def test_can_be_set_to_true(self):
        """report_download_pdf should accept True."""
        env = mock_env_vars(
            os_environ,
            {
                "GTI_API_KEY": "fake-key",
                "GTI_REPORT_DOWNLOAD_PDF": "true",
            },
        )
        config = GTIReportConfig()
        assert config.report_download_pdf is True  # noqa: S101
        env.stop()

    def test_can_be_set_to_false_explicitly(self):
        """report_download_pdf should accept explicit False."""
        env = mock_env_vars(
            os_environ,
            {
                "GTI_API_KEY": "fake-key",
                "GTI_REPORT_DOWNLOAD_PDF": "false",
            },
        )
        config = GTIReportConfig()
        assert config.report_download_pdf is False  # noqa: S101
        env.stop()


# =====================
# ClientAPIReport.download_report_pdf Tests
# =====================


class TestClientAPIReportDownloadPdf:
    """Tests for ClientAPIReport.download_report_pdf()."""

    @pytest.mark.asyncio
    async def test_download_report_pdf_success(self, dummy_config, logger):
        """Should return PDF bytes when API and download both succeed."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(
            return_value={"data": "https://storage.example.com/report.pdf"}
        )

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        fake_pdf = b"%PDF-1.4 fake content"
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.read = AsyncMock(return_value=fake_pdf)

        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_session_ctx)

        mock_client_session_ctx = AsyncMock()
        mock_client_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_client_session_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "connector.src.custom.client_api.report.client_api_report.ClientSession",
            return_value=mock_client_session_ctx,
        ):
            result = await client.download_report_pdf("report--test-123")

        assert result == fake_pdf  # noqa: S101
        mock_api_client.call_api.assert_called_once()
        call_kwargs = mock_api_client.call_api.call_args
        assert "X-Apikey" in call_kwargs.kwargs["headers"]  # noqa: S101
        assert call_kwargs.kwargs["headers"]["X-Apikey"] == "fake-key"  # noqa: S101

    @pytest.mark.asyncio
    async def test_download_report_pdf_no_url_in_response(self, dummy_config, logger):
        """Should return None when API returns no PDF URL."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(return_value={"data": None})

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        result = await client.download_report_pdf("report--test-123")
        assert result is None  # noqa: S101

    @pytest.mark.asyncio
    async def test_download_report_pdf_empty_response(self, dummy_config, logger):
        """Should return None when API returns empty dict."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(return_value={})

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        result = await client.download_report_pdf("report--test-123")
        assert result is None  # noqa: S101

    @pytest.mark.asyncio
    async def test_download_report_pdf_non_dict_response(self, dummy_config, logger):
        """Should return None when API returns non-dict."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(return_value="unexpected")

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        result = await client.download_report_pdf("report--test-123")
        assert result is None  # noqa: S101

    @pytest.mark.asyncio
    async def test_download_report_pdf_http_error(self, dummy_config, logger):
        """Should return None when PDF download returns HTTP error."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(
            return_value={"data": "https://storage.example.com/report.pdf"}
        )

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        mock_response = AsyncMock()
        mock_response.status = 404

        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_session_ctx)

        mock_client_session_ctx = AsyncMock()
        mock_client_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_client_session_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "connector.src.custom.client_api.report.client_api_report.ClientSession",
            return_value=mock_client_session_ctx,
        ):
            result = await client.download_report_pdf("report--test-123")

        assert result is None  # noqa: S101

    @pytest.mark.asyncio
    async def test_download_report_pdf_api_exception(self, dummy_config, logger):
        """Should return None when API call raises an exception."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(side_effect=Exception("API error"))

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        result = await client.download_report_pdf("report--test-123")
        assert result is None  # noqa: S101

    @pytest.mark.asyncio
    async def test_download_report_pdf_non_https_url(self, dummy_config, logger):
        """Should return None when API returns a non-HTTPS URL."""
        mock_api_client = AsyncMock()
        mock_api_client.call_api = AsyncMock(
            return_value={"data": "http://insecure.example.com/report.pdf"}
        )

        client = ClientAPIReport(
            config=dummy_config,
            logger=logger,
            api_client=mock_api_client,
            fetcher_factory=MagicMock(),
        )

        result = await client.download_report_pdf("report--test-123")
        assert result is None  # noqa: S101


# =====================
# ClientAPI delegation Tests
# =====================


class TestClientAPIDelegation:
    """Tests for ClientAPI.download_report_pdf() delegation."""

    @pytest.mark.asyncio
    async def test_delegates_to_report_client(self, dummy_config, logger):
        """ClientAPI.download_report_pdf should delegate to report_client."""
        with (
            patch.object(ClientAPI, "_create_api_client"),
            patch.object(ClientAPI, "_create_fetcher_factory"),
        ):
            client = ClientAPI(config=dummy_config, logger=logger)

        mock_report_client = AsyncMock()
        mock_report_client.download_report_pdf = AsyncMock(return_value=b"pdf-bytes")
        client.report_client = mock_report_client

        result = await client.download_report_pdf("report--abc")
        assert result == b"pdf-bytes"  # noqa: S101
        mock_report_client.download_report_pdf.assert_called_once_with("report--abc")


# =====================
# OrchestratorReport._attach_report_pdf Tests
# =====================


class TestAttachReportPdf:
    """Tests for OrchestratorReport._attach_report_pdf()."""

    def _make_fake_report(self, report_id="report--test", name="Test Report"):
        """Create a fake report object."""
        attrs = MagicMock()
        attrs.name = name
        report = MagicMock()
        report.id = report_id
        report.attributes = attrs
        return report

    def _make_fake_stix_entity(self, entity_type, custom_properties=None):
        """Create a fake STIX entity with type and custom_properties."""
        entity = MagicMock()
        entity.type = entity_type
        entity.custom_properties = (
            custom_properties if custom_properties is not None else {}
        )
        return entity

    @pytest.mark.asyncio
    async def test_attach_pdf_success(self, dummy_config_with_pdf, logger):
        """Should attach PDF to the report entity's custom_properties."""
        fake_pdf = b"%PDF-1.4 test content here"
        report = self._make_fake_report()
        report_entity = self._make_fake_stix_entity("report")
        identity_entity = self._make_fake_stix_entity("identity")
        entities = [identity_entity, report_entity]

        with patch.object(OrchestratorReport, "__init__", return_value=None):
            orchestrator = OrchestratorReport.__new__(OrchestratorReport)
            orchestrator.logger = logger
            orchestrator.config = dummy_config_with_pdf
            orchestrator.client_api = AsyncMock()
            orchestrator.client_api.download_report_pdf = AsyncMock(
                return_value=fake_pdf
            )

            result = await orchestrator._attach_report_pdf(report, entities)

        assert len(result) == 2  # noqa: S101
        report_ent = [e for e in result if e.type == "report"][0]
        files = report_ent.custom_properties["x_opencti_files"]
        assert len(files) == 1  # noqa: S101
        assert files[0]["name"] == "Test Report.pdf"  # noqa: S101
        assert files[0]["mime_type"] == "application/pdf"  # noqa: S101
        assert files[0]["no_trigger_import"] is True  # noqa: S101
        decoded = base64.b64decode(files[0]["data"])
        assert decoded == fake_pdf  # noqa: S101

    @pytest.mark.asyncio
    async def test_attach_pdf_returns_unchanged_when_download_fails(
        self, dummy_config_with_pdf, logger
    ):
        """Should return entities unchanged when PDF download returns None."""
        report = self._make_fake_report()
        report_entity = self._make_fake_stix_entity("report")
        entities = [report_entity]

        with patch.object(OrchestratorReport, "__init__", return_value=None):
            orchestrator = OrchestratorReport.__new__(OrchestratorReport)
            orchestrator.logger = logger
            orchestrator.config = dummy_config_with_pdf
            orchestrator.client_api = AsyncMock()
            orchestrator.client_api.download_report_pdf = AsyncMock(return_value=None)

            result = await orchestrator._attach_report_pdf(report, entities)

        assert result is entities  # noqa: S101
        assert (
            "x_opencti_files" not in report_entity.custom_properties
            or report_entity.custom_properties.get("x_opencti_files") is None
            or len(report_entity.custom_properties.get("x_opencti_files", [])) == 0
        )  # noqa: S101

    @pytest.mark.asyncio
    async def test_attach_pdf_uses_report_id_when_no_name(
        self, dummy_config_with_pdf, logger
    ):
        """Should fall back to report ID for filename when name is missing."""
        fake_pdf = b"%PDF-1.4"
        report = self._make_fake_report(report_id="report--fallback-id", name=None)
        report.attributes.name = None
        report_entity = self._make_fake_stix_entity("report")
        entities = [report_entity]

        with patch.object(OrchestratorReport, "__init__", return_value=None):
            orchestrator = OrchestratorReport.__new__(OrchestratorReport)
            orchestrator.logger = logger
            orchestrator.config = dummy_config_with_pdf
            orchestrator.client_api = AsyncMock()
            orchestrator.client_api.download_report_pdf = AsyncMock(
                return_value=fake_pdf
            )

            result = await orchestrator._attach_report_pdf(report, entities)

        files = result[0].custom_properties["x_opencti_files"]
        assert "report--fallback-id" in files[0]["name"]  # noqa: S101

    @pytest.mark.asyncio
    async def test_attach_pdf_sanitizes_filename(self, dummy_config_with_pdf, logger):
        """Should sanitize special characters in the report name for the filename."""
        fake_pdf = b"%PDF-1.4"
        report = self._make_fake_report(name="Report: <Test> / Special!")
        report_entity = self._make_fake_stix_entity("report")
        entities = [report_entity]

        with patch.object(OrchestratorReport, "__init__", return_value=None):
            orchestrator = OrchestratorReport.__new__(OrchestratorReport)
            orchestrator.logger = logger
            orchestrator.config = dummy_config_with_pdf
            orchestrator.client_api = AsyncMock()
            orchestrator.client_api.download_report_pdf = AsyncMock(
                return_value=fake_pdf
            )

            result = await orchestrator._attach_report_pdf(report, entities)

        files = result[0].custom_properties["x_opencti_files"]
        filename = files[0]["name"]
        assert "<" not in filename  # noqa: S101
        assert ">" not in filename  # noqa: S101
        assert "/" not in filename  # noqa: S101
        assert ":" not in filename  # noqa: S101
        assert filename.endswith(".pdf")  # noqa: S101

    @pytest.mark.asyncio
    async def test_attach_pdf_with_none_custom_properties(
        self, dummy_config_with_pdf, logger
    ):
        """Should handle entity with custom_properties=None."""
        fake_pdf = b"%PDF-1.4"
        report = self._make_fake_report()
        report_entity = self._make_fake_stix_entity("report", custom_properties=None)
        entities = [report_entity]

        with patch.object(OrchestratorReport, "__init__", return_value=None):
            orchestrator = OrchestratorReport.__new__(OrchestratorReport)
            orchestrator.logger = logger
            orchestrator.config = dummy_config_with_pdf
            orchestrator.client_api = AsyncMock()
            orchestrator.client_api.download_report_pdf = AsyncMock(
                return_value=fake_pdf
            )

            result = await orchestrator._attach_report_pdf(report, entities)

        files = result[0].custom_properties["x_opencti_files"]
        assert len(files) == 1  # noqa: S101
