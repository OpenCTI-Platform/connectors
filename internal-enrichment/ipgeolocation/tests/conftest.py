"""Shared test fixtures."""

import os
import sys

import pytest

# Ensure src is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.markdown_generator import MarkdownGenerator
from src.models import IPIntelligence
from src.risk_scorer import RiskScorer
from src.stix_mapper import STIXMapper
from tests.mock_responses import MOCK_IPGEO_CLEAN, MOCK_IPGEO_FULL


@pytest.fixture
def high_risk_intel() -> IPIntelligence:
    """An IP with multiple threat flags (VPN + proxy + known attacker)."""
    return IPIntelligence.from_ipgeo_response(MOCK_IPGEO_FULL)


@pytest.fixture
def clean_intel() -> IPIntelligence:
    """A clean IP (Google DNS) with no threat flags."""
    return IPIntelligence.from_ipgeo_response(MOCK_IPGEO_CLEAN)


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer()


@pytest.fixture
def mapper() -> STIXMapper:
    return STIXMapper(
        author_name="IPGeolocation.io",
        default_marking="TLP:WHITE",
        confidence=80,
    )


@pytest.fixture
def md_gen() -> MarkdownGenerator:
    return MarkdownGenerator()
