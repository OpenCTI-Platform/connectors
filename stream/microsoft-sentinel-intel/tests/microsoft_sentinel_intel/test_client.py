import pytest
from microsoft_sentinel_intel import ConnectorClient
from microsoft_sentinel_intel.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture


@pytest.mark.usefixtures("mocked_api_client", "mock_microsoft_sentinel_intel_config")
def test_client_uses_client_secret_credential_for_app_registration_auth_type(
    mocker: MockerFixture,
) -> None:
    mocked_client_secret_credential = mocker.patch(
        "microsoft_sentinel_intel.client.ClientSecretCredential"
    )
    mocked_default_azure_credential = mocker.patch(
        "microsoft_sentinel_intel.client.DefaultAzureCredential"
    )

    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.to_helper_config())
    ConnectorClient(helper=helper, config=config)

    mocked_client_secret_credential.assert_called_once_with(
        tenant_id=config.microsoft_sentinel_intel.tenant_id,
        client_id=config.microsoft_sentinel_intel.client_id,
        client_secret=config.microsoft_sentinel_intel.client_secret.get_secret_value(),
    )
    mocked_default_azure_credential.assert_not_called()


@pytest.mark.usefixtures(
    "mocked_api_client", "mock_microsoft_sentinel_intel_azure_credential_config"
)
def test_client_uses_default_azure_credential_for_azure_credential_auth_type(
    mocker: MockerFixture,
) -> None:
    mocked_client_secret_credential = mocker.patch(
        "microsoft_sentinel_intel.client.ClientSecretCredential"
    )
    mocked_default_azure_credential = mocker.patch(
        "microsoft_sentinel_intel.client.DefaultAzureCredential"
    )

    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.to_helper_config())
    ConnectorClient(helper=helper, config=config)

    mocked_default_azure_credential.assert_called_once_with()
    mocked_client_secret_credential.assert_not_called()
