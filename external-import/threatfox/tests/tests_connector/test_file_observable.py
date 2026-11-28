from unittest.mock import MagicMock

import pytest
from src.__main__ import FeedRow, ThreatFox


@pytest.fixture
def connector():
    connector = ThreatFox.__new__(ThreatFox)
    connector.helper = MagicMock()
    connector.identity = {
        "standard_id": "identity--5d1c3a4e-9a43-4f0e-9d0c-2f5b7a1e8c11"
    }
    connector.create_indicators = False
    connector.default_x_opencti_score = 50
    connector.x_opencti_score_hash = None
    return connector


# Expected IDs are the OpenCTI File standard IDs, derived from the hashes only.
@pytest.mark.parametrize(
    "ioc_type, ioc_value, standard_id",
    [
        (
            "md5_hash",
            "44d88612fea8a8f36de82e1278abb02f",
            "file--5a0c55a1-48a3-5003-9776-42946d1054cb",
        ),
        (
            "sha1_hash",
            "3395856ce81f2b7382dee72602f798b642f14140",
            "file--9ab9e221-3b13-5bec-a726-e4b9685bd852",
        ),
        (
            "sha256_hash",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "file--00f91c70-2975-500a-919c-fe3a0d6c125a",
        ),
    ],
)
def test_file_observable_id_matches_opencti_standard_id(
    connector, ioc_type, ioc_value, standard_id
):
    ioc = MagicMock(spec=FeedRow)
    ioc.type = ioc_type
    ioc.value = ioc_value
    ioc.reference = ""
    ioc.tags = []

    observable, _ = connector.process_row_observable(ioc)

    assert observable.id == standard_id
