import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.append(str(Path(__file__).parent.parent / "src"))

import pytest
from connector.services.client_api import ProofpointEtReputationClient
from pydantic import SecretStr

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def proofpoint_client():
    """Create a ProofpointEtReputationClient with mocked dependencies."""
    helper = MagicMock()
    api_token = SecretStr("fake-api-token")
    return ProofpointEtReputationClient(helper, api_token)


@pytest.fixture
def fixture_data_iprepdata():
    """Load IP reputation sample data."""
    with open(FIXTURES_DIR / "data_sample_iprepdata.json", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def fixture_data_domainrepdata():
    """Load domain reputation sample data."""
    with open(FIXTURES_DIR / "data_sample_domainrepdata.json", encoding="utf-8") as f:
        return json.load(f)
