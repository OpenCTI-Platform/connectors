import pytest
from base_connector import ConfigRetrievalError
from main import main


def test_main_invalid_configuration() -> None:
    with pytest.raises(ConfigRetrievalError) as exc_info:
        main()
    assert "Invalid OpenCTI configuration." == exc_info.value.args[0]
