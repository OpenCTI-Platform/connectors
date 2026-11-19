from unittest.mock import MagicMock

import pytest
from connector.connector import IOCExtractorConnector
from connectors_sdk.models.enums import TLPLevel


@pytest.fixture
def connector() -> IOCExtractorConnector:
    """Build a connector without running `__init__`, with a mocked config."""
    connector = object.__new__(IOCExtractorConnector)
    connector.config = MagicMock()
    connector.config.connector.max_tlp = TLPLevel.AMBER
    return connector


@pytest.mark.parametrize(
    "object_marking",
    [
        [],
        [{"definition_type": "TLP", "definition": "TLP:GREEN"}],
        [{"definition_type": "PAP", "definition": "PAP:RED"}],
    ],
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
