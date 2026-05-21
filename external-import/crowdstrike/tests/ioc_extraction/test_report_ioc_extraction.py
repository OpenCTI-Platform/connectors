"""Tests for IOC extraction integration in report building."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from crowdstrike_feeds_connector.report.builder import ReportBundleBuilder
from crowdstrike_feeds_connector.report.importer import ReportImporter
from stix2 import TLP_AMBER, Bundle, Identity, MarkingDefinition

# =====================
# Fixtures
# =====================


@pytest.fixture
def fake_report_data() -> dict:
    faker_dir = Path(__file__).parent.parent / "faker"
    with open(faker_dir / "api_report.json", "r") as f:
        return json.load(f)


@pytest.fixture
def author_identity() -> Identity:
    return Identity(  # pylint: disable=W9101
        name="CrowdStrike",
        identity_class="organization",
    )


@pytest.fixture
def tlp_marking() -> MarkingDefinition:
    return TLP_AMBER


@pytest.fixture
def crowdstrike_config() -> dict[str, str]:
    return {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": f"{uuid4()}",
        "CONNECTOR_ID": f"{uuid4()}",
        "CONNECTOR_NAME": "CrowdStrike Test",
        "CONNECTOR_SCOPE": "crowdstrike",
        "CROWDSTRIKE_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_CLIENT_ID": f"{uuid4()}",
        "CROWDSTRIKE_CLIENT_SECRET": f"{uuid4()}",
    }


# =====================
# Builder tests
# =====================


def _build_report_bundle(
    report_data: dict,
    author: Identity,
    tlp_marking: MarkingDefinition,
    extracted_observables=None,
) -> Bundle:
    builder = ReportBundleBuilder(
        report=report_data,
        author=author,
        source_name="CrowdStrike",
        object_markings=[tlp_marking],
        report_status=0,
        report_type="threat-report",
        confidence_level=80,
        extracted_observables=extracted_observables,
    )
    return builder.build()


def test_builder_includes_extracted_observables_in_bundle(
    fake_report_data, author_identity, tlp_marking
):
    """Extracted observables should appear in the bundle objects."""
    from stix2 import IPv4Address

    obs = IPv4Address(value="45.33.32.156")  # pylint: disable=W9101
    bundle = _build_report_bundle(
        fake_report_data, author_identity, tlp_marking, extracted_observables=[obs]
    )

    bundle_types = [getattr(o, "type", None) for o in bundle.objects]
    assert "ipv4-addr" in bundle_types


def test_builder_includes_extracted_observables_in_report_object_refs(
    fake_report_data, author_identity, tlp_marking
):
    """Extracted observables should be referenced in the report's object_refs."""
    from stix2 import IPv4Address

    obs = IPv4Address(value="45.33.32.156")  # pylint: disable=W9101
    bundle = _build_report_bundle(
        fake_report_data, author_identity, tlp_marking, extracted_observables=[obs]
    )

    report_obj = next(o for o in bundle.objects if getattr(o, "type", None) == "report")
    assert obs.id in report_obj.object_refs


def test_builder_without_extracted_observables(
    fake_report_data, author_identity, tlp_marking
):
    """Bundle should still build correctly when no observables are extracted."""
    bundle = _build_report_bundle(
        fake_report_data, author_identity, tlp_marking, extracted_observables=None
    )

    report_obj = next(o for o in bundle.objects if getattr(o, "type", None) == "report")
    assert report_obj is not None


# =====================
# Importer helper tests
# =====================


def test_get_report_text_content_returns_description(fake_report_data):
    """Should return the description field."""
    text = ReportImporter._get_report_text_content(fake_report_data)
    assert len(text) > 0


def test_get_report_text_content_falls_back_to_description():
    """Should fall back to description when rich_text_description is missing."""
    report = {"description": "plain text description"}
    text = ReportImporter._get_report_text_content(report)
    assert text == "plain text description"


def test_get_report_text_content_falls_back_to_short_description():
    """Should fall back to short_description as last resort."""
    report = {"short_description": "short desc"}
    text = ReportImporter._get_report_text_content(report)
    assert text == "short desc"


def test_get_report_text_content_returns_empty_when_no_content():
    """Should return empty string when no text fields are present."""
    text = ReportImporter._get_report_text_content({})
    assert text == ""


# =====================
# Report with IOCs in description
# =====================


def test_report_with_iocs_in_description_produces_observables(
    fake_report_data, author_identity, tlp_marking
):
    """When report description contains IOCs and extract_iocs is on,
    the bundle should contain the corresponding observables."""
    from crowdstrike_feeds_services.utils.ioc_extractor import (
        VALID_IOC_TYPES,
        extract_iocs,
    )
    from crowdstrike_feeds_services.utils.observables import ObservableProperties

    # Inject IOCs into the report description
    fake_report_data["rich_text_description"] = None
    fake_report_data["description"] = (
        "The actor used 45.33.32.156 as C2. "
        "Domain evil.example.com was also observed. "
        "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    text = ReportImporter._get_report_text_content(fake_report_data)
    iocs = extract_iocs(text, list(VALID_IOC_TYPES))

    # Build observables the same way the importer does
    observables = []
    for ioc in iocs:
        factory = ReportImporter._IOC_OBSERVABLE_FACTORIES.get(ioc.type)
        if factory:
            props = ObservableProperties(
                value=ioc.value,
                created_by=author_identity,
                labels=["extracted-from-report"],
                score=0,
                object_markings=[tlp_marking],
            )
            observables.append(factory(props))

    assert len(observables) >= 3  # at least ipv4, domain, sha256

    bundle = _build_report_bundle(
        fake_report_data,
        author_identity,
        tlp_marking,
        extracted_observables=observables,
    )

    bundle_types = {getattr(o, "type", None) for o in bundle.objects}
    assert "ipv4-addr" in bundle_types
    assert "domain-name" in bundle_types
    assert "file" in bundle_types  # SHA-256 creates a File observable
