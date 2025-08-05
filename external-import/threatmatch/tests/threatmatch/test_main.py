import pytest
from main import main


def test_main_invalid_configuration() -> None:
    # Make sure there s no config file loaded
    with pytest.raises(ValueError) as exc_info:
        main()
    assert "An URL must be set" == exc_info.value.args[0]
