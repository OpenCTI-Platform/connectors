import os
import sys
from unittest.mock import MagicMock

# pycti imports python-magic at import time; mock before connector package loads.
mock_pycti = MagicMock()
mock_pycti.STIX_EXT_OCTI_SCO = (
    "extension-definition--eccbc87e-7fd4-45c3-863c-f8ad55952641"
)
mock_pycti.Location.generate_id = MagicMock(return_value="location--test")
mock_pycti.OpenCTIConnectorHelper = MagicMock
mock_pycti.OpenCTIStix2 = MagicMock
mock_pycti.StixSightingRelationship.generate_id = MagicMock(
    return_value="sighting--test"
)
sys.modules.setdefault("pycti", mock_pycti)
sys.modules.setdefault("stix2", MagicMock())

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
