import pytest
from conftest import CENSYS_URL
from connectors_sdk.connectors.internal_hunt import HuntExecutionError


def test_a_refused_run_names_the_key_to_fix(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given Censys refusing the token
    requests_mock.post(CENSYS_URL, status_code=401)

    # When/Then the run fails naming the variable to fix
    with pytest.raises(
        HuntExecutionError,
        match="Censys refused the personal access token: check INFRASTRUCTURE_TRACKER_CENSYS_TOKEN",
    ):
        connector_factory().process_message(hunt_event)


def test_declares_the_accounts_of_its_sources(connector_factory):
    # Given/When/Then each source account is declared and documented
    connector = connector_factory()
    assert [name for name, _ in connector.required_permissions][0] == (
        "Censys Platform: Global Search API"
    )
    assert connector.documentation_url.endswith("#infrastructure-tracker")
