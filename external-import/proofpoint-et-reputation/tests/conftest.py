import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from connector import ProofpointEtReputationClient


@pytest.fixture
def proofpoint_client():
    """
    Used to simulate the ProofPoint API client.
    This fixture provides an instance of `ProofpointEtReputationClient` with mocked configuration and helper objects.

    Returns:
         ProofpointEtReputationClient: A mocked instance of the client ProofPoint ET Reputation.
    """
    mock_config = MagicMock()
    mock_helper = MagicMock()
    return ProofpointEtReputationClient(mock_helper, mock_config)


@pytest.fixture
def fixture_data_iprepdata():
    """
    This fixture loads the content of `data_sample_iprepdata.json`,
    representing sample data for IP reputation, and returns it as a dictionary.

    Returns:
        dict: Parsed content of the JSON file containing IP reputation data.
    """
    return load_file("data_sample_iprepdata.json")


@pytest.fixture
def fixture_data_domainrepdata():
    """
    This fixture loads the content of `data_sample_domainrepdata.json`,
    representing sample data for domain reputation, and returns it as a dictionary.

    Returns:
        dict: Parsed content of the JSON file containing domain reputation data.
    """
    return load_file("data_sample_domainrepdata.json")


def load_file(filename: str) -> dict:
    """
    Load the content of a JSON file and return it as a dictionary.
    Args:
        filename (str): The name of the JSON file to load.
    Returns:
        dict: A dictionary containing the data parsed from the JSON file.
    """
    filepath = Path(__file__).parent / "fixtures" / filename
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)
