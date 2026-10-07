"""Tests for LivehuntBuilder individual methods — Phase 4.

These tests exercise individual builder methods in isolation:
- `create_alert()` — alert creation with custom prefix
- `create_file()` — file observable + SHA-256 indicator
- `create_file()` — without incident
- `create_rule()` — YARA rule creation
- `retrieve_labels()` — label extraction
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from connectors_sdk.models import (
    File,
    Incident,
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
    md5: str = "b" * 32,
    sha1: str = "c" * 40,
    size: int = 100000,
    names: List[str] = None,
    meaningful_name: str = "malware.exe",
    type_tags: List[str] = None,
    tags: List[str] = None,
    type_extension: str = "peexe",
    last_analysis_stats: Dict[str, Any] = None,
    last_analysis_results: Dict[str, Any] = None,
    notification_date: float = None,
    hunting_info: Dict[str, Any] = None,
) -> SimpleNamespace:
    """Build a mock vtobj that mimics a VirusTotal Livehunt notification."""
    if names is None:
        names = ["malware.exe"]
    if type_tags is None:
        type_tags = []
    if tags is None:
        tags = []
    if last_analysis_stats is None:
        last_analysis_stats = {
            "malicious": 5,
            "suspicious": 1,
            "harmless": 0,
            "undetected": 50,
            "clean": 50,
        }
    if last_analysis_results is None:
        last_analysis_results = {
            "Antivirus_A": {"result": "Malware"},
            "Antivirus_B": {"result": "Malware"},
        }
    if notification_date is None:
        notification_date = datetime.now(timezone.utc).timestamp()
    if hunting_info is None:
        hunting_info = {"rule_name": "Test Rule"}

    return SimpleNamespace(
        id=f"notif-{sha256}",
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        size=size,
        names=names,
        meaningful_name=meaningful_name,
        type_tags=type_tags,
        tags=tags,
        type_extension=type_extension,
        last_analysis_stats=last_analysis_stats,
        last_analysis_results=last_analysis_results,
        _context_attributes={
            "sources": [{"id": "yara-rule-1", "label": "Test YARA"}],
            "notification_date": notification_date,
            "hunting_info": hunting_info,
            "tags": [],
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
        "get_malware_config": False,
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
# Phase 4 Tests — Méthodes individuelles
# ──────────────────────────────────────────────────────────────────────


class TestCreateAlert:
    """Test 9: create_alert() — création d'alerte."""

    def test_create_alert_with_custom_prefix(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When create_alert is called, it should create an incident with custom prefix."""
        vtobj = make_vt_notification(sha256="a" * 64)

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            alert_prefix="[CUSTOM] VT Alert",
        )

        external_ref = builder.create_external_reference(
            "https://www.virustotal.com/gui/file/abc",
            "Test Reference",
        )

        incident = builder.create_alert(vtobj, external_ref)

        # Verify incident was created
        assert incident is not None
        assert isinstance(incident, Incident)
        assert "[CUSTOM] VT Alert" in incident.name
        assert "Test Rule" in incident.name
        assert vtobj.sha256 in incident.name

        # Verify incident was added to bundle
        assert len(builder.bundle) > 0
        stix_objects = [obj for obj in builder.bundle if hasattr(obj, "type")]
        incident_objects = [obj for obj in stix_objects if obj.type == "incident"]
        assert len(incident_objects) == 1

    def test_create_alert_returns_none_when_exists(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When alert already exists in OpenCTI, create_alert should return None."""
        vtobj = make_vt_notification(sha256="a" * 64)

        # Simulate alert already exists
        mock_helper.api.incident.read.return_value = {
            "id": "existing-alert-id",
            "name": "Existing Alert",
        }

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        external_ref = builder.create_external_reference(
            "https://www.virustotal.com/gui/file/abc",
            "Test Reference",
        )

        incident = builder.create_alert(vtobj, external_ref)

        # Verify None is returned
        assert incident is None

        # Verify no incident was added to bundle (author + marking may still be there)
        stix_objects = [obj for obj in builder.bundle if hasattr(obj, "type")]
        incident_objects = [obj for obj in stix_objects if obj.type == "incident"]
        assert len(incident_objects) == 0


class TestCreateFile:
    """Test 10-11: create_file() — création de fichier."""

    def test_create_file_with_indicator(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When create_file is called with create_file_indicators=True, it should create file + indicator."""
        vtobj = make_vt_notification(sha256="a" * 64)

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            create_file_indicators=True,
        )

        # Create alert first to get incident
        external_ref = builder.create_external_reference(
            "https://www.virustotal.com/gui/file/abc",
            "Test Reference",
        )
        incident = builder.create_alert(vtobj, external_ref)

        # Create file linked to incident
        file_obj = builder.create_file(vtobj, incident)

        # Verify file was created
        assert file_obj is not None
        assert isinstance(file_obj, File)
        assert file_obj.hashes["SHA-256"] == "a" * 64

        # Verify file was added to bundle
        stix_objects = [obj for obj in builder.bundle if hasattr(obj, "type")]
        assert len(stix_objects) >= 1

        # Verify indicator was created
        indicators = [obj for obj in stix_objects if obj.type == "indicator"]
        assert len(indicators) == 1
        assert "SHA-256" in indicators[0].pattern

        # Verify relationships were created
        relationships = [obj for obj in stix_objects if obj.type == "relationship"]
        assert len(relationships) >= 1  # based-on + related-to

    def test_create_file_without_incident(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When create_alert=False, no incident should be created."""
        vtobj = make_vt_notification(sha256="a" * 64)

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            create_alert=False,
            create_file_indicators=True,
        )

        # Create file without incident
        file_obj = builder.create_file(vtobj, incident=None)

        # Verify file was created
        assert file_obj is not None
        assert isinstance(file_obj, File)

        # Verify no incident in bundle
        stix_objects = [obj for obj in builder.bundle if hasattr(obj, "type")]
        incidents = [obj for obj in stix_objects if obj.type == "incident"]
        assert len(incidents) == 0

        # Verify file indicator was created (no incident, so no related-to)
        indicators = [obj for obj in stix_objects if obj.type == "indicator"]
        assert len(indicators) == 1


class TestCreateRule:
    """Test 12: create_yara_rule() — création de règle YARA."""

    def test_create_yara_rule_with_incident_and_file(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When create_rule is called, it should create YARA indicator linked to incident and file."""
        # Mock the ruleset response
        mock_ruleset = MagicMock()
        mock_ruleset.rules = """
rule TestRule {
    meta:
        date = "2024-01-01"
    strings:
        $a = "malware"
    condition:
        $a
}
"""
        mock_vt_client.get_object.return_value = mock_ruleset

        builder = build_test_builder(
            mock_vt_client,
            mock_helper,
            author,
            tlp_marking,
            create_yara_rule=True,
        )

        # Create alert and file first
        vtobj = make_vt_notification(sha256="a" * 64)
        external_ref = builder.create_external_reference(
            "https://www.virustotal.com/gui/file/abc",
            "Test Reference",
        )
        incident = builder.create_alert(vtobj, external_ref)
        file_obj = builder.create_file(vtobj, incident)

        # Create YARA rule
        builder.create_rule(
            ruleset_id="yara_rule_1",
            rule_name="TestRule",
            incident=incident,
            file=file_obj,
        )

        # Verify YARA indicator was created
        stix_objects = [obj for obj in builder.bundle if hasattr(obj, "type")]
        indicators = [obj for obj in stix_objects if obj.type == "indicator"]
        assert len(indicators) == 1
        assert indicators[0].pattern_type == "yara"
        assert "TestRule" in indicators[0].name

        # Verify relationships to incident and file
        relationships = [obj for obj in stix_objects if obj.type == "relationship"]
        assert len(relationships) >= 2  # at least related-to incident + related-to file

    def test_create_yara_rule_without_incident_or_file(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When create_rule is called without incident or file, only indicator should be created."""
        mock_ruleset = MagicMock()
        mock_ruleset.rules = """
rule SimpleRule {
    strings:
        $a = "test"
    condition:
        $a
}
"""
        mock_vt_client.get_object.return_value = mock_ruleset

        # Override format_date to handle None
        mock_helper.api.stix2.format_date = MagicMock(
            side_effect=lambda dt: dt.isoformat() if dt else "2024-01-01T00:00:00Z"
        )

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        builder.create_rule(
            ruleset_id="yara-rule-2",
            rule_name="SimpleRule",
            incident=None,
            file=None,
        )

        # Verify only indicator was created (no relationships)
        stix_objects = [obj for obj in builder.bundle if hasattr(obj, "type")]
        indicators = [obj for obj in stix_objects if obj.type == "indicator"]
        relationships = [obj for obj in stix_objects if obj.type == "relationship"]
        assert len(indicators) == 1
        assert len(relationships) == 0


class TestRetrieveLabels:
    """Test 15: retrieve_labels() — extraction des labels."""

    def test_retrieve_labels_from_hunting_info(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When vtobj has hunting_info, the rule_name should be converted to a label."""
        vtobj = make_vt_notification(
            sha256="a" * 64,
            hunting_info={"rule_name": "My Custom Rule"},
        )

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        labels = builder.retrieve_labels(vtobj)

        assert "vt:my_custom_rule" in labels

    def test_retrieve_labels_from_yara_sources(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When vtobj has yara sources, the source label should be converted to a label."""
        vtobj = make_vt_notification(
            sha256="a" * 64,
            hunting_info={"rule_name": "Test Rule"},
        )
        # Override _context_attributes to include yara source
        vtobj._context_attributes["sources"] = [
            {"id": "yara-1", "label": "My Yara Rule", "type": "hunting_ruleset"}
        ]

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        labels = builder.retrieve_labels(vtobj)

        # Should have both the hunting rule label and the yara label
        # Note: yara_label_prefix is empty by default, so no "vt:" prefix for YARA labels
        assert "my_yara_rule" in labels

    def test_retrieve_labels_empty(
        self, mock_vt_client, mock_helper, author, tlp_marking
    ):
        """When vtobj has no tags or hunting_info, labels should be empty."""
        vtobj = make_vt_notification(
            sha256="a" * 64,
            hunting_info={"rule_name": None},
        )
        vtobj._context_attributes["tags"] = []
        vtobj._context_attributes["sources"] = []

        builder = build_test_builder(mock_vt_client, mock_helper, author, tlp_marking)

        labels = builder.retrieve_labels(vtobj)

        assert labels == []
