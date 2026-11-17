import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def connector():
    from microsoft_sentinel_incidents_connector.connector import (
        MicrosoftSentinelIncidentsConnector,
    )

    conn = object.__new__(MicrosoftSentinelIncidentsConnector)
    conn.helper = MagicMock()
    conn.client = MagicMock()
    conn.converter_to_stix = MagicMock()
    conn.config = MagicMock()
    conn.converter_to_stix.create_incident.return_value = MagicMock(id="incident--fake")
    conn.converter_to_stix.create_custom_case_incident.return_value = MagicMock()
    return conn


@pytest.fixture
def make_alert():
    def _make_alert(entities):
        return {
            "Entities": json.dumps(entities),
            "Techniques": "[]",
            "SubTechniques": "[]",
        }

    return _make_alert
