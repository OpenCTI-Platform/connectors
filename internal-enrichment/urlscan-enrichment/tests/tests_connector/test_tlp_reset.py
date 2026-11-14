from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from urlscan_enrichment_services import UrlscanConnector


@pytest.fixture
def connector():
    connector = UrlscanConnector.__new__(UrlscanConnector)
    connector.tlp = None
    connector.config = MagicMock()
    connector.config.connector.max_tlp = "amber"
    return connector


def _entity(tlp=None):
    markings = [{"definition_type": "TLP", "definition": tlp}] if tlp else []
    return {"objectMarking": markings}


def _check(connector, entity):
    try:
        result = connector.extract_and_check_markings(entity)
    except ValueError:
        return False
    return True if result is None else result


def test_extract_and_check_markings_should_not_reuse_tlp_of_previous_message(
    connector,
):
    assert _check(connector, _entity("TLP:RED")) is False

    # A following entity without any marking must not inherit TLP:RED
    assert _check(connector, _entity()) is True
    assert connector.tlp is None
