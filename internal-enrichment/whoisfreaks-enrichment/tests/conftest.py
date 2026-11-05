import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.append(os.path.join(os.path.dirname(__file__), "tests_connector"))

from connector.converter_to_stix import ConverterToStix  # noqa: E402
from connector.markdown_generator import MarkdownGenerator  # noqa: E402
from mock_responses import (  # noqa: E402
    MOCK_WHOIS_FULL,
    MOCK_WHOIS_REDACTED,
    MOCK_WHOIS_UNREGISTERED,
)
from whoisfreaks_client.models import WhoisRecord  # noqa: E402


@pytest.fixture
def full_record() -> WhoisRecord:
    """A registered domain with contacts and name servers."""
    return WhoisRecord.from_response(MOCK_WHOIS_FULL)


@pytest.fixture
def redacted_record() -> WhoisRecord:
    """A registered domain whose contacts are redacted for privacy."""
    return WhoisRecord.from_response(MOCK_WHOIS_REDACTED)


@pytest.fixture
def unregistered_record() -> WhoisRecord:
    """An available (not registered) domain."""
    return WhoisRecord.from_response(MOCK_WHOIS_UNREGISTERED)


@pytest.fixture
def md_gen() -> MarkdownGenerator:
    return MarkdownGenerator()


@pytest.fixture
def converter() -> ConverterToStix:
    return ConverterToStix(tlp_level="clear")
