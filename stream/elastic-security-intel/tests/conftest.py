import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

ELASTIC_URL = "http://elastic.test:9200"
INDEX_NAME = "logs-ti_custom_opencti.indicator"
DELETE_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_delete_by_query"
DOC_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_doc"


class FakeLogger:
    def info(self, *args, **kwargs):
        pass

    debug = warning = error = info


class FakeHelper:
    connector_logger = FakeLogger()


class FakeConfig:
    load = {}
    elastic_url = ELASTIC_URL
    elastic_api_key = "dummy"
    elastic_client_cert = None
    elastic_client_key = None
    elastic_ca_cert = None
    elastic_verify_ssl = False
    elastic_index_name = INDEX_NAME
    elastic_kibana_url = None
    elastic_opencti_external_url = "http://opencti.test"


@pytest.fixture
def helper():
    return FakeHelper()


@pytest.fixture
def config():
    return FakeConfig()
