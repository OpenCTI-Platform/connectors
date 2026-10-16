from conftest import CENSYS_URL, censys_answer

CHECK_EVENT = {
    "event_type": "INTERNAL_HUNT",
    "mode": "check",
    "connection_check": {"id": "check-1"},
}


def _checks(helper):
    check_id, checks = helper.report_hunt_connection_check.call_args.args
    assert check_id == "check-1"
    return checks


def test_connection_test_runs_one_search_per_source(
    connector_factory, helper, requests_mock
):
    # Given a Censys key allowed to search
    requests_mock.post(CENSYS_URL, json=censys_answer([]))

    # When OpenCTI asks for a connection test
    message = connector_factory().process_message(dict(CHECK_EVENT))

    # Then the source passes with a single, unlikely-to-match search
    assert _checks(helper) == [
        {
            "name": "Censys Platform",
            "ok": True,
            "message": "Censys Platform accepted the key and ran a search.",
        }
    ]
    assert "OpenCTI connection test" in requests_mock.last_request.text
    assert message == "Connection test passed"


def test_connection_test_names_the_key_a_source_refuses(
    connector_factory, helper, requests_mock
):
    # Given Censys refusing the token
    requests_mock.post(CENSYS_URL, status_code=401)

    # When/Then the check names the variable to fix
    connector_factory().process_message(dict(CHECK_EVENT))
    [check] = _checks(helper)
    assert check["ok"] is False
    assert check["message"].endswith(
        "Censys refused the personal access token: check INFRASTRUCTURE_TRACKER_CENSYS_TOKEN."
    )


def test_declares_the_accounts_of_its_sources(connector_factory):
    # Given/When/Then each source account is declared and documented
    connector = connector_factory()
    assert [name for name, _ in connector.required_permissions][0] == (
        "Censys Platform: Global Search API"
    )
    assert connector.documentation_url.endswith("#infrastructure-tracker")
