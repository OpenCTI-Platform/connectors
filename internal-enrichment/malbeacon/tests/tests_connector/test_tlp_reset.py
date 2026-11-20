from unittest.mock import MagicMock

import pytest
from main import MalBeaconConnector
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def connector():
    connector = MalBeaconConnector.__new__(MalBeaconConnector)
    connector.tlp = None
    connector.helper = MagicMock()
    connector.helper.check_max_tlp.side_effect = OpenCTIConnectorHelper.check_max_tlp
    connector.config = MagicMock(max_tlp="TLP:AMBER")
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
