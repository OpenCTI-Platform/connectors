import json
import os
from unittest.mock import Mock

import pytest
from crowdstrike_services import CrowdstrikeClient


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = Mock()
    request.cls.mock_client = CrowdstrikeClient(request.cls.mock_helper)

    yield


@pytest.fixture(scope="class")
def stream_event(request):
    request.cls.ioc_event_create = load_file("event_create_indicator_sample.json")
    request.cls.ioc_event_update = load_file("event_update_indicator_sample.json")
    request.cls.ioc_event_delete = load_file("event_delete_indicator_sample.json")
    request.cls.ioc_data = load_file("data_stream_sample.json")


@pytest.fixture(scope="class")
def api_response(request):
    request.cls.res_file_hash = load_file("response_file_hash_sample.json")


def load_file(filename: str) -> dict:
    """
    Utility function to load a json file to a dict
    :param filename: Filename in string
    :return:
    """
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)
