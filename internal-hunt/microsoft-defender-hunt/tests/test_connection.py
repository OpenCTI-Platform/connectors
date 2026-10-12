from conftest import HUNTING_URL, TOKEN_URL, answer, hunting_queries
from connectors_sdk.connectors.internal_hunt import RunDeadline


def _checks(connector):
    return [
        (check.name, check.ok, check.message)
        for check in connector.connection_checks(RunDeadline(30))
    ]


def test_declares_its_permissions_and_tests_its_search(connector_factory):
    # Given/When the connector is started
    connector = connector_factory()

    # Then it declares its least-privilege permissions, its setup documentation,
    # a test search in one of its languages, and what a refused account lacks
    assert [name for name, _ in connector.required_permissions] == [
        "ThreatHunting.Read.All"
    ]
    assert connector.documentation_url.startswith(
        "https://docs.opencti.io/latest/usage/hunt-connectors/#"
    )
    query = connector.connection_test_query()
    assert (query.language, query.query) == ("kql", "DeviceInfo | take 1")
    assert query.language in connector.languages
    assert set(connector.client.access_denied_hints) == {401, 403}


def test_connection_checks_pass_when_the_tenant_answers(
    connector_factory, requests_mock
):
    # Given a tenant holding one onboarded device
    requests_mock.post(HUNTING_URL, json=answer([("DeviceName", "String")], [["ws1"]]))

    # When the connection is tested
    checks = _checks(connector_factory())

    # Then the token and the advanced hunting query both pass, over the last 7 days
    assert [(name, ok) for name, ok, _ in checks] == [
        ("Microsoft Entra ID", True),
        ("ThreatHunting.Read.All", True),
    ]
    assert "device telemetry" in checks[1][2]
    assert hunting_queries(requests_mock) == ["DeviceInfo | take 1"]
    assert requests_mock.last_request.json()["Timespan"] == "P7D"


def test_connection_checks_warn_without_device_telemetry(
    connector_factory, requests_mock
):
    # Given a tenant without device seen in the last 7 days
    requests_mock.post(HUNTING_URL, json=answer([("DeviceName", "String")], []))

    # When/Then the permission passes, the message explaining the empty answer
    [_, (name, ok, message)] = _checks(connector_factory())
    assert (name, ok) == ("ThreatHunting.Read.All", True)
    assert "onboard devices" in message


def test_connection_checks_pass_without_defender_for_endpoint(
    connector_factory, requests_mock
):
    # Given a tenant without the DeviceInfo table
    requests_mock.post(
        HUNTING_URL,
        status_code=400,
        json={
            "error": {
                "code": "BadRequest",
                "message": "Failed to resolve table expression named 'DeviceInfo'",
            }
        },
    )

    # When/Then the permission passes: advanced hunting answered the query
    [_, (name, ok, message)] = _checks(connector_factory())
    assert (name, ok) == ("ThreatHunting.Read.All", True)
    assert "no DeviceInfo table" in message
    assert "Failed to resolve table" in message


def test_connection_checks_name_the_missing_permission(
    connector_factory, requests_mock
):
    # Given an app registration without ThreatHunting.Read.All
    requests_mock.post(
        HUNTING_URL,
        status_code=403,
        json={"error": {"code": "Forbidden", "message": "Missing role permissions"}},
    )

    # When/Then the permission check fails and names the permission to grant
    [_, (name, ok, message)] = _checks(connector_factory())
    assert (name, ok) == ("ThreatHunting.Read.All", False)
    assert "admin consent" in message


def test_connection_checks_stop_when_the_credentials_are_refused(
    connector_factory, requests_mock
):
    # Given Microsoft Entra ID refusing the client secret
    connector = connector_factory()
    requests_mock.post(
        TOKEN_URL,
        status_code=401,
        json={"error": "invalid_client", "error_description": "AADSTS7000215"},
    )

    # When/Then only the authentication is reported, failed, naming the settings
    [(name, ok, message)] = _checks(connector)
    assert (name, ok) == ("Microsoft Entra ID", False)
    assert "MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET" in message
    assert hunting_queries(requests_mock) == []
