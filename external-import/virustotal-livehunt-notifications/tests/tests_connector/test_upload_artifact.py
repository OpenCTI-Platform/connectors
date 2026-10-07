"""Tests for upload_artifact_opencti — Phase 6.

This test exercises the file artifact upload to OpenCTI:
- `upload_artifact_opencti()` — downloads file from VT and uploads to OpenCTI
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from connectors_sdk.models import (
    OrganizationAuthor,
    TLPMarking,
)
from livehunt.builder import LivehuntBuilder

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_vt_client():
    """Return a mock vt.Client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_helper():
    """Return a mock OpenCTIConnectorHelper."""
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connector_logger.debug = MagicMock()
    helper.connector_logger.info = MagicMock()
    helper.connector_logger.warning = MagicMock()
    helper.connector_logger.error = MagicMock()
    helper.api = MagicMock()
    helper.api.incident = MagicMock()
    helper.api.incident.read = MagicMock(return_value=None)
    helper.api.stix2 = MagicMock()
    helper.api.stix2.format_date = MagicMock(
        side_effect=lambda dt: (
            dt.isoformat() if dt and hasattr(dt, "isoformat") else str(dt)
        )
    )
    helper.api.stix_cyber_observable = MagicMock()
    helper.api.stix_cyber_observable.upload_artifact = MagicMock(
        return_value={"id": "artifact-123"}
    )
    helper.metric = MagicMock()
    helper.metric.inc = MagicMock()
    return helper


@pytest.fixture
def author():
    """Return a default SDK author."""
    return OrganizationAuthor(name="VirusTotal Livehunt")


@pytest.fixture
def tlp_marking():
    """Return a default TLP marking."""
    return TLPMarking(level="amber+strict")


def make_vt_notification(
    sha256: str = "a" * 64,
    meaningful_name: str = "malware.exe",
    malware_config: Dict[str, Any] = None,
    hunting_info: Dict[str, Any] = None,
    names: List[str] = None,
    last_analysis_results: Dict[str, Any] = None,
    type_tags: List[str] = None,
    tags: List[str] = None,
) -> SimpleNamespace:
    """Build a mock vtobj with optional malware config."""
    if malware_config is None:
        malware_config = {}
    if hunting_info is None:
        hunting_info = {"rule_name": "Test Rule"}
    if names is None:
        names = ["malware.exe"]
    if last_analysis_results is None:
        last_analysis_results = {
            "Antivirus_A": {"result": "Malware"},
            "Antivirus_B": {"result": "Malware"},
        }
    if type_tags is None:
        type_tags = []
    if tags is None:
        tags = []
    return SimpleNamespace(
        id=f"notif-{sha256}",
        sha256=sha256,
        meaningful_name=meaningful_name,
        malware_config=malware_config,
        names=names,
        last_analysis_results=last_analysis_results,
        type_tags=type_tags,
        tags=tags,
        _context_attributes={
            "hunting_info": hunting_info,
            "sources": [],
            "tags": [],
            "notification_date": datetime.now(timezone.utc).timestamp(),
        },
    )


def build_test_builder(
    mock_vt_client,
    mock_helper,
    author,
    tlp_marking,
    **kwargs,
) -> LivehuntBuilder:
    """Create a LivehuntBuilder with minimal config for testing."""
    defaults = {
        "tag": None,
        "create_alert": True,
        "max_age_days": 30,
        "create_file": True,
        "upload_artifact": False,
        "create_yara_rule": False,
        "delete_notification": False,
        "extensions": [],
        "min_file_size": 0,
        "max_file_size": 10000000,
        "min_positives": 1,
        "alert_prefix": "[VT] Livehunt",
        "av_list": ["Antivirus_A", "Antivirus_B"],
        "yara_label_prefix": "",
        "livehunt_label_prefix": "vt:",
        "livehunt_tag_prefix": "vt:",
        "enable_label_enrichment": True,
        "get_malware_config": True,
        "create_file_indicators": False,
        "create_domain_name_indicators": False,
        "create_ip_indicators": False,
        "create_url_indicators": False,
        "limit": None,
    }
    defaults.update(kwargs)
    return LivehuntBuilder(
        client=mock_vt_client,
        helper=mock_helper,
        author=author,
        tlp_marking=tlp_marking,
        **defaults,
    )


# ──────────────────────────────────────────────────────────────────────
# Phase 6 Tests — Upload artifact
# ──────────────────────────────────────────────────────────────────────


class TestUploadArtifact:
    """Test 21: upload_artifact_opencti() — upload de fichier à OpenCTI."""

    def test_upload_artifact_sends_file_to_opencti(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When upload_artifact is called, it should download the file from VT and upload to OpenCTI."""
        import io

        vtobj = make_vt_notification(sha256="a" * 64, meaningful_name="malware.exe")

        # Mock the file download
        file_contents = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        mock_vt_client.download_file = MagicMock()
        mock_vt_client.download_file.return_value = None

        # Simulate BytesIO being written to
        def mock_download(sha256, file_obj):
            file_obj.write(file_contents)

        mock_vt_client.download_file.side_effect = mock_download

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        # Call upload_artifact_opencti
        result = builder.upload_artifact_opencti(vtobj)

        # Verify the file was downloaded with correct sha256
        mock_vt_client.download_file.assert_called_once()
        call_args = mock_vt_client.download_file.call_args
        assert call_args[0][0] == "a" * 64
        assert isinstance(call_args[0][1], io.BytesIO)

        # Verify OpenCTI upload was called with correct parameters
        mock_helper.api.stix_cyber_observable.upload_artifact.assert_called_once()
        call_kwargs = mock_helper.api.stix_cyber_observable.upload_artifact.call_args[1]

        # Verify upload parameters
        assert call_kwargs["file_name"] == "malware.exe"
        assert call_kwargs["data"] == file_contents
        assert (
            call_kwargs["mime_type"] == "application/octet-stream"
        )  # magic detects binary
        assert (
            call_kwargs["x_opencti_description"]
            == "Downloaded from Virustotal Livehunt Notifications."
        )
        assert call_kwargs["createdBy"] == author.id

        # Verify return value
        assert result == {"id": "artifact-123"}

    def test_upload_artifact_uses_sha256_when_no_meaningful_name(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When vtobj has no meaningful_name, sha256 should be used as filename."""
        # Create a vtobj without meaningful_name attribute
        vtobj = SimpleNamespace(
            id="notif-b" * 64,
            sha256="b" * 64,
            malware_config={},
            names=["file.bin"],
            last_analysis_results={"Antivirus_A": {"result": "Malware"}},
            type_tags=[],
            tags=[],
            _context_attributes={
                "hunting_info": {"rule_name": "Test Rule"},
                "sources": [],
                "tags": [],
                "notification_date": datetime.now(timezone.utc).timestamp(),
            },
        )

        # Mock the file download
        file_contents = b"PK\x03\x04"  # ZIP magic bytes
        mock_vt_client.download_file = MagicMock()

        def mock_download(sha256, file_obj):
            file_obj.write(file_contents)

        mock_vt_client.download_file.side_effect = mock_download

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        # Call upload_artifact_opencti
        builder.upload_artifact_opencti(vtobj)

        # Verify filename is sha256 when meaningful_name is not present
        call_kwargs = mock_helper.api.stix_cyber_observable.upload_artifact.call_args[1]
        assert call_kwargs["file_name"] == "b" * 64
