import json
import os
from unittest.mock import MagicMock, Mock

import pytest
from src.secops_siem_services import CTIConverter


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = MagicMock()
    request.cls.mock_config = Mock()
    request.cls.CTIConverter = CTIConverter(
        request.cls.mock_helper, request.cls.mock_config
    )

    yield


def load_file(filename: str) -> dict:
    """
    Utility function to load a json file to a dict
    :param filename: Filename in string
    :return:
    """
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)


@pytest.fixture(scope="class")
def event_data_samples(request):
    request.cls.fake_ioc_data = load_file("octi_indicator_sample.json")
    request.cls.fake_ioc_data_no_id = load_file("octi_indicator_no_id_sample.json")
    request.cls.fake_observable_values = load_file("octi_observable_values_sample.json")
    request.cls.fake_metadata = load_file("udm_metadata_sample.json")
