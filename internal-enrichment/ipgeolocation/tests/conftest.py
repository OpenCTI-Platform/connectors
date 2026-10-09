import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.append(os.path.join(os.path.dirname(__file__), "tests_connector"))

from connector.converter_to_stix import ConverterToStix  # noqa: E402
from connector.markdown_generator import MarkdownGenerator  # noqa: E402
from connector.risk_scorer import RiskScorer  # noqa: E402
from ipgeolocation_client.models import IPIntelligence  # noqa: E402
from mock_responses import MOCK_IPGEO_CLEAN, MOCK_IPGEO_FULL  # noqa: E402


@pytest.fixture
def high_risk_intel() -> IPIntelligence:
    """An IP with several threat flags (VPN, proxy, known attacker)."""
    return IPIntelligence.from_ipgeo_response(MOCK_IPGEO_FULL)


@pytest.fixture
def clean_intel() -> IPIntelligence:
    """A clean IP (Google DNS) with no threat flags."""
    return IPIntelligence.from_ipgeo_response(MOCK_IPGEO_CLEAN)


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer()


@pytest.fixture
def md_gen() -> MarkdownGenerator:
    return MarkdownGenerator()


@pytest.fixture
def converter() -> ConverterToStix:
    return ConverterToStix(tlp_level="clear")
