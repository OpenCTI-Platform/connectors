"""Tests for the escaping of values in STIX patterns."""

import logging
from unittest.mock import MagicMock

import pytest
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.mappers.gti_iocs.gti_url_to_stix_url import GTIUrlToSTIXUrl
from connector.src.custom.mappers.gti_iocs.stix_pattern import escape_pattern_value
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
)
from connector.src.custom.models.gti.gti_url_model import GTIURLData
from stix2.pattern_visitor import create_pattern_object  # type: ignore
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

BACKSLASH = "\\"
QUOTED_URL = f"https://example.com/it's{BACKSLASH}here"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("plain", "plain"),
        ("it's", f"it{BACKSLASH}'s"),
        (f"back{BACKSLASH}slash", f"back{BACKSLASH * 2}slash"),
    ],
)
def test_escape_pattern_value(value: str, expected: str) -> None:
    """Backslashes and single quotes are escaped."""
    # Given a value
    # When it is escaped
    # Then it matches the STIX grammar
    assert escape_pattern_value(value) == expected  # noqa: S101


def test_delta_url_with_quote_gives_valid_pattern() -> None:
    """An IOC delta URL with a quote and a backslash produces a parsable pattern."""
    # Given a delta converter and a URL entry with a quote and a backslash
    config = MagicMock(
        indicator_scoring="threat_score",
        extended_descriptions=False,
        indicator_subentities=[],
    )
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry(
        id="url-id", type="url", attributes=IOCDeltaAttributes(url=QUOTED_URL)
    )
    # When it is converted
    indicator = converter._convert_url(entry)
    # Then the pattern parses
    assert indicator is not None  # noqa: S101
    create_pattern_object(indicator.pattern)


def test_collection_url_with_quote_gives_valid_pattern() -> None:
    """A collection URL with a quote and a backslash produces a parsable pattern."""
    # Given a URL mapper for a URL with a quote and a backslash
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id="marking-definition--00000000-0000-4000-8000-000000000001",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    url = GTIURLData(id="url-id", type="url", attributes={"url": QUOTED_URL})
    mapper = GTIUrlToSTIXUrl(url, organization, marking)
    # When its pattern is built
    # Then it parses
    create_pattern_object(mapper._build_stix_pattern())
