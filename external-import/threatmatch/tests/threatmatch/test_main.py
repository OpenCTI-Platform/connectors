import pytest
from main import main
from pytest_mock import MockerFixture
from threatmatch.config import ConfigRetrievalError


@pytest.mark.usefixtures("mocked_helper", "mock_config")
def test_main() -> None:
    # Make sure there s no config file loaded
    main()


@pytest.mark.usefixtures("mocked_helper")
def test_main_invalid_configuration(mocker: MockerFixture) -> None:
    # Ensure local config is not loaded
    mocker.patch("threatmatch.config.ConnectorSettings.model_config", {"yaml_file": ""})
    # Make sure there s no config file loaded
    with pytest.raises(ConfigRetrievalError) as exc_info:
        main()
    assert "Invalid OpenCTI configuration." == exc_info.value.args[0]
