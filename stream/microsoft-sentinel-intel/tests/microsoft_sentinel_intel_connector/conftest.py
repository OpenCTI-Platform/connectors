from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> MagicMock:
    return mocker.patch("pycti.OpenCTIConnectorHelper", MagicMock())
