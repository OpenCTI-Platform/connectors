from conftest import QUERIES_URL, done, launched_queries, mock_query
from sentinelone_hunt.connector import EDR_FILTER

CHECK_EVENT = {
    "event_type": "INTERNAL_HUNT",
    "mode": "check",
    "connection_check": {"id": "check-1"},
}


def _checks(helper):
    check_id, checks = helper.report_hunt_connection_check.call_args.args
    assert check_id == "check-1"
    return checks


def test_declares_its_permissions_and_tests_its_search(connector_factory):
    # Given/When the connector is started
    connector = connector_factory()

    # Then it declares its least-privilege permissions, its setup documentation,
    # a test search in one of its languages, and what a refused account lacks
    assert connector.required_permissions
    assert connector.documentation_url.startswith(
        "https://docs.opencti.io/latest/usage/hunt-connectors/#"
    )
    assert connector.connection_test_query().language in connector.languages
    assert set(connector.client.access_denied_hints) == {401, 403}


def test_connection_test_reads_one_edr_event(connector_factory, helper, requests_mock):
    # Given EDR telemetry in the last 15 minutes
    mock_query(requests_mock, done(["timestamp"], [["2026-10-16T06:00:00Z"]]))

    # When OpenCTI asks for a connection test
    connector_factory().process_message(dict(CHECK_EVENT))

    # Then one EDR event is read (the full page is then counted), with the field
    # names checked, and the search passes
    assert launched_queries(requests_mock) == [
        f"{EDR_FILTER} | limit 1",
        f"{EDR_FILTER} | group opencti_hit_count = count()",
    ]
    assert requests_mock.request_history[0].json()["scheme"] == "edr"
    checks = _checks(helper)
    assert [(check["name"], check["ok"]) for check in checks] == [("Search", True)]


def test_connection_test_of_the_whole_data_lake(
    connector_factory, helper, requests_mock
):
    # Given a connector searching the whole Data Lake
    mock_query(requests_mock, done([], []))

    # When OpenCTI asks for a connection test
    connector_factory({"sentinelone_hunt": {"edr_only": False}}).process_message(
        dict(CHECK_EVENT)
    )

    # Then any parsed event is searched, without the EDR schema check
    assert launched_queries(requests_mock) == ["dataSource.name = * | limit 1"]
    assert "scheme" not in requests_mock.request_history[0].json()
    assert _checks(helper)[0]["ok"] is True


def test_connection_test_names_what_a_refused_token_lacks(
    connector_factory, helper, requests_mock
):
    # Given a token SentinelOne refuses
    requests_mock.post(QUERIES_URL, status_code=401, json={"message": "Unauthorized"})

    # When OpenCTI asks for a connection test
    connector_factory().process_message(dict(CHECK_EVENT))

    # Then the search fails with what to fix
    (check,) = _checks(helper)
    assert check["ok"] is False
    assert "SENTINELONE_HUNT_API_TOKEN" in check["message"]
