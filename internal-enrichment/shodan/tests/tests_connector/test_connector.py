from types import SimpleNamespace

import pytest
from connector.connector import ShodanConnector


@pytest.fixture
def connector() -> ShodanConnector:
    """Build a connector without running `__init__` (no OpenCTI or Shodan call)."""
    connector = object.__new__(ShodanConnector)
    connector.config = SimpleNamespace(connector=SimpleNamespace(max_tlp="amber"))
    return connector


@pytest.mark.parametrize(
    "object_marking",
    [[], [{"definition_type": "TLP", "definition": "TLP:GREEN"}]],
)
def test_extract_and_check_markings_accepts_entity_within_max_tlp(
    connector, object_marking
):
    connector._extract_and_check_markings({"objectMarking": object_marking})


@pytest.mark.parametrize(
    "object_marking",
    [
        [{"definition_type": "TLP", "definition": "TLP:RED"}],
        # Every TLP of the entity is checked, not only the last one
        [
            {"definition_type": "TLP", "definition": "TLP:RED"},
            {"definition_type": "TLP", "definition": "TLP:GREEN"},
        ],
    ],
)
def test_extract_and_check_markings_refuses_entity_above_max_tlp(
    connector, object_marking
):
    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector._extract_and_check_markings({"objectMarking": object_marking})
