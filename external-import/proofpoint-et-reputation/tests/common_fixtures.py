from unittest.mock import Mock
import json
from pathlib import Path
import pytest


@pytest.fixture
def mock_helper():
    return Mock()


@pytest.fixture
def mock_config():
    return Mock()


@pytest.fixture
def fixture_data_iprepdata():
    return load_file("data_sample_iprepdata.json")


@pytest.fixture
def fixture_data_domainrepdata():
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
