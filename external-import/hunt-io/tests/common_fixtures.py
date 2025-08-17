from unittest.mock import Mock

import pytest  # type: ignore


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = Mock()

    yield
