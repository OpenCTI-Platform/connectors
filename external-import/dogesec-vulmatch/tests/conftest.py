import os
import sys
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def mock_session(mocker: MockerFixture) -> MagicMock:
    """Mock the HTTP session used to call the Vulmatch API."""
    session = MagicMock()
    mocker.patch("connector.requests.Session", return_value=session)
    return session
