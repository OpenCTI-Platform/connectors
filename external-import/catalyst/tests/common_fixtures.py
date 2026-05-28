import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest


class StixObject:
    """A simple class to represent STIX objects with type attribute"""

    def __init__(self, obj_type, obj_id, **kwargs):
        self.type = obj_type
        self.id = obj_id
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __str__(self):
        return f"{self.type}--{self.id}"


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = Mock()
    request.cls.mock_helper.connector_logger = Mock()

    yield


@pytest.fixture
def mock_opencti_helper():
    """
    Return a mock OpenCTI helper
    """
    mock_helper = Mock()
    mock_helper.connector_logger = Mock()
    mock_helper.api = Mock()
    mock_helper.api.work = Mock()

    return mock_helper


@pytest.fixture
def mock_config():
    """
    Return a mock config object with default values
    """
    mock_config = Mock()
    mock_config.duration_period = "P1D"
    mock_config.api_base_url = "https://test.catalyst.api"
    mock_config.api_key = "test-api-key"
    mock_config.tlp_level = "amber"
    mock_config.update_existing_data = False
    mock_config.tlp_filter = "AMBER,RED"
    mock_config.category_filter = "RESEARCH"
    mock_config.sync_days_back = 7
    mock_config.create_observables = True
    mock_config.create_indicators = True

    mock_config.load = {
        "connector": {
            "duration_period": mock_config.duration_period,
            "update_existing_data": mock_config.update_existing_data,
        },
        "catalyst": {
            "base_url": mock_config.api_base_url,
            "api_key": mock_config.api_key,
            "tlp_level": mock_config.tlp_level,
            "tlp_filter": mock_config.tlp_filter,
            "category_filter": mock_config.category_filter,
            "sync_days_back": mock_config.sync_days_back,
            "create_observables": mock_config.create_observables,
            "create_indicators": mock_config.create_indicators,
        },
    }

    return mock_config


@pytest.fixture
def sample_stix_report():
    """
    Return a sample STIX report object
    """
    return {
        "type": "report",
        "id": "report--test-id",
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "name": "Test Report",
        "description": "Test report description",
        "published": datetime.now().isoformat(),
        "object_refs": ["indicator--test-id-1", "indicator--test-id-2"],
    }


@pytest.fixture
def sample_stix_indicator():
    """
    Return a sample STIX indicator object
    """
    return {
        "type": "indicator",
        "id": "indicator--test-id-1",
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "name": "Test Indicator",
        "description": "Test indicator description",
        "pattern": "[ipv4-addr:value = '192.168.1.1']",
        "pattern_type": "stix",
        "valid_from": datetime.now().isoformat(),
        "indicator_types": ["malicious-activity"],
    }


@pytest.fixture
def sample_stix_object_report():
    """
    Return a sample StixObject report
    """
    return StixObject(
        "report",
        "test-id",
        name="Test Report",
        description="Test report description",
        created=datetime.now().isoformat(),
        modified=datetime.now().isoformat(),
        published=datetime.now().isoformat(),
        object_refs=["indicator--test-id-1", "indicator--test-id-2"],
    )


@pytest.fixture
def sample_stix_object_indicator():
    """
    Return a sample StixObject indicator
    """
    return StixObject(
        "indicator",
        "test-id-1",
        name="Test Indicator",
        description="Test indicator description",
        pattern="[ipv4-addr:value = '192.168.1.1']",
        pattern_type="stix",
        valid_from=datetime.now().isoformat(),
        indicator_types=["malicious-activity"],
        created=datetime.now().isoformat(),
        modified=datetime.now().isoformat(),
    )


@pytest.fixture
def fixtures_path():
    """
    Return the path to the fixtures directory
    """
    return Path(__file__).parent / "fixtures"


def load_test_data(filename):
    """
    Load test data from a JSON file in the fixtures directory
    """
    fixtures_dir = Path(__file__).parent / "fixtures"
    file_path = fixtures_dir / filename

    if not file_path.exists():
        raise FileNotFoundError(f"Test data file not found: {file_path}")

    with open(file_path, "r") as f:
        return json.load(f)
