"""Tests for the GTI tags of IOCs as labels (GTI_IOC_TAGS_AS_LABELS)."""

import logging
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.mappers.gti_iocs.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.gti_iocs.ioc_assessment import ioc_tag_labels
from connector.src.custom.models.gti.gti_file_model import FileModel, GTIFileData
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
    IOCDeltaRelationships,
)
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TAGS = ["peexe", "overlay", "peexe", ""]
LABELS = ["peexe", "overlay"]


@pytest.mark.parametrize(
    "tags, expected", [(TAGS, LABELS), ([], None), (None, None), ([""], None)]
)
def test_ioc_tag_labels(tags: list[str] | None, expected: list[str] | None) -> None:
    """Tags are deduplicated in GTI order and empty tags dropped."""
    # Given GTI tags
    # When they are turned into labels
    # Then duplicates and empty tags are removed
    assert ioc_tag_labels(tags) == expected  # noqa: S101


@pytest.mark.parametrize("enabled, expected", [(True, LABELS), (False, None)])
def test_collection_ioc_labels(enabled: bool, expected: list[str] | None) -> None:
    """Collection IOC indicators and observables get the tags when enabled."""
    # Given a tagged file
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    file = GTIFileData(
        id=SHA256, type="file", attributes=FileModel(sha256=SHA256, tags=TAGS)
    )
    mapper = GTIFileToSTIXFile(file, organization, marking, ioc_tags_as_labels=enabled)
    # When it is converted
    observable, indicator, _ = mapper.to_stix()
    # Then both carry the labels only when enabled
    assert indicator.labels == expected  # noqa: S101
    assert observable.get("x_opencti_labels") == expected  # noqa: S101


@pytest.mark.parametrize("enabled, expected", [(True, LABELS), (False, [])])
def test_delta_indicator_labels(enabled: bool, expected: list[str]) -> None:
    """IOC delta indicators get the tags when enabled."""
    # Given a delta converter and a tagged domain entry
    config = MagicMock(
        indicator_min_score=None,
        indicator_require_malware_family=False,
        indicator_require_threat_actor=False,
        indicator_scoring="threat_score",
        indicator_min_verdict="any",
        extended_descriptions=False,
        ioc_tags_as_labels=enabled,
        indicator_subentities=[],
    )
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry(
        id="example.com",
        type="domain",
        attributes=IOCDeltaAttributes(tags=TAGS),
        relationships=IOCDeltaRelationships(),
    )
    # When it is converted
    indicator = next(
        obj for obj in converter.convert(entry.model_dump()) if obj.type == "indicator"
    )
    # Then the labels follow the option
    assert list(indicator.get("labels", [])) == expected  # noqa: S101
