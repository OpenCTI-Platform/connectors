"""Tests for the GTI threat category and severity of file IOCs."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_iocs.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.gti_iocs.ioc_assessment import (
    ioc_tag_labels,
    threat_category,
    threat_severity_section,
)
from connector.src.custom.models.gti.gti_file_model import FileModel, GTIFileData
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SEVERITY = {
    "threat_severity_level": "SEVERITY_HIGH",
    "level_description": "Detected by many engines and similar to known malware.",
    "threat_severity_data": {"popular_threat_category": "trojan"},
}


def _mapper(**options: bool) -> GTIFileToSTIXFile:
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    file = GTIFileData(
        id=SHA256,
        type="file",
        attributes=FileModel(
            sha256=SHA256, tags=["peexe", "trojan"], threat_severity=SEVERITY
        ),
    )
    return GTIFileToSTIXFile(file, organization, marking, **options)


def test_threat_category() -> None:
    """The category comes from the threat severity data, when present."""
    # Given files with and without a threat severity
    # When the category is read
    # Then it is the GTI popular threat category
    category = threat_category(FileModel(threat_severity=SEVERITY))
    assert category == "trojan"  # noqa: S101
    assert threat_category(FileModel()) is None  # noqa: S101


@pytest.mark.parametrize(
    "tags, category, expected",
    [
        (["peexe"], "trojan", ["peexe", "trojan"]),
        (["trojan"], "trojan", ["trojan"]),
        (None, "trojan", ["trojan"]),
        (None, None, None),
    ],
)
def test_labels_include_category(
    tags: list[str] | None, category: str | None, expected: list[str] | None
) -> None:
    """The category follows the tags, without duplicates."""
    # Given GTI tags and a threat category
    # When the labels are built
    # Then the category is added once
    assert ioc_tag_labels(tags, category) == expected  # noqa: S101


def test_threat_severity_section() -> None:
    """The severity level, its explanation and the category are described."""
    # Given a file with a threat severity
    # When its section is built
    # Then each detail is listed
    section = threat_severity_section(FileModel(threat_severity=SEVERITY))
    assert section == (  # noqa: S101
        "**GTI threat severity**\n\n"
        "- Level: High\n"
        "- Explanation: Detected by many engines and similar to known malware.\n"
        "- Threat category: trojan"
    )
    assert threat_severity_section(FileModel()) is None  # noqa: S101


def test_file_mapper_labels_and_description() -> None:
    """File indicators get the category label and the severity description."""
    # Given a file mapper with labels and extended descriptions enabled
    mapper = _mapper(ioc_tags_as_labels=True, extended_descriptions=True)
    # When it is converted
    observable, indicator, _ = mapper.to_stix()
    # Then the category is a label and the severity is described
    assert indicator.labels == ["peexe", "trojan"]  # noqa: S101
    assert observable.x_opencti_labels == ["peexe", "trojan"]  # noqa: S101
    assert "**GTI threat severity**" in indicator.description  # noqa: S101


def test_file_mapper_default() -> None:
    """By default, the category and severity are not imported."""
    # Given a file mapper with default options
    # When it is converted
    _, indicator, _ = _mapper().to_stix()
    # Then there is no label or description
    assert indicator.labels is None  # noqa: S101
    assert indicator.description is None  # noqa: S101
