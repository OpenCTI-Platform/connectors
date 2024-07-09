import os

import pytest
from src.rflib import RFClient

RF_API_KEY = "module_token"
RF_API_KEY_LEGACY = "RF_TOKEN"


class DummyHelper:
    """Skeleton object to mimic OpenCTIConnectorHelper"""

    def log_info(self, message):
        print("INFO: {}".format(message))

    def log_error(self, message):
        print("ERROR: {}".format(message))

    def log_warning(self, message):
        print("WARNING: {}".format(message))


@pytest.fixture(scope="session")
def vcr_config():
    return {
        "filter_headers": [("X-RFToken", "bmljZSB0cnkgOikpKSk=")],
    }


@pytest.fixture()
def rf_token():
    return os.environ.get(RF_API_KEY)


@pytest.fixture()
def rf_legacy_token():
    return os.environ.get(RF_API_KEY_LEGACY)


@pytest.fixture()
def opencti_helper():
    return DummyHelper()


@pytest.fixture
def rf_client(rf_token, opencti_helper):
    return RFClient(rf_token, opencti_helper, header="OpenCTI-notes/1.0")


@pytest.fixture
def tas(rf_client):
    return rf_client.get_threat_actors()
