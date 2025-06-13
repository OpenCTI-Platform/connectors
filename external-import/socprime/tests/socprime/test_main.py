import os
from unittest.mock import Mock

import pytest
from main import main


@pytest.mark.usefixtures("mock_socprime_config")
def test_main(
    mocked_opencti_helper: Mock,
    mocked_mitre_attack_requests: Mock,
    mocked_tdm_api_client_requests: Mock,
) -> None:

    with pytest.raises(SystemExit):
        # Have to set the environment variable to simulate the run and terminate mode
        # and avoid the infinite loop in the connector
        os.environ["CONNECTOR_RUN_AND_TERMINATE"] = "true"
        main()

    mocked_opencti_helper.force_ping.assert_called_once()
    mocked_mitre_attack_requests.get.assert_called_once()
    assert mocked_tdm_api_client_requests.request.call_count == 4
