import pytest
from main import main
from threatmatch.config import ConfigRetrievalError


@pytest.mark.usefixtures("mocked_helper", "mock_config")
def test_main() -> None:
    # Make sure there s no config file loaded
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert 0 == exc_info.value.args[0]


@pytest.mark.usefixtures("mocked_helper")
def test_main_invalid_configuration() -> None:
    # Make sure there s no config file loaded
    with pytest.raises(ConfigRetrievalError) as exc_info:
        main()
    assert "Invalid OpenCTI configuration." == exc_info.value.args[0]
