import pytest
from main import main


@pytest.mark.usefixtures("mocked_helper")
def test_main_invalid_configuration() -> None:
    # Make sure there s no config file loaded
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert 0 == exc_info.value.args[0]
