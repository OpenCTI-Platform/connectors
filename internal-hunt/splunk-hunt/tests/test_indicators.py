import re

from conftest import NAMESPACE
from connectors_sdk.connectors.internal_hunt import HuntIoc, IocBatch
from splunk_hunt.connector import build_ioc_lookup, spl_string

INDICATOR = {
    "standard_id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
    "entity_type": "Indicator",
    "name": "C2 address",
}
IOCS = [
    {
        "key": "k-ip",
        "observable_type": "IPv4-Addr",
        "value": "198.51.100.7",
        "sources": [INDICATOR],
    },
    {
        "key": "k-ip-2",
        "observable_type": "IPv4-Addr",
        "value": "198.51.100.8",
        "sources": [INDICATOR],
    },
    {
        "key": "k-url",
        "observable_type": "Url",
        "value": 'https://evil.example.com/a"b',
        "sources": [],
    },
]


def _indicator_event(hunt_event, **overrides):
    hunt_event["hunt"].update(
        {"hunt_type": "indicators", "sigma_rule": None, "iocs": IOCS}
    )
    hunt_event.update(overrides)
    return hunt_event


def _mock_job(requests_mock, rows):
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(
        f"{NAMESPACE}/search/jobs/sid-1",
        json={"entry": [{"content": {"isDone": True, "resultCount": len(rows)}}]},
    )
    requests_mock.get(
        f"{NAMESPACE}/search/v2/jobs/sid-1/results", json={"results": rows}
    )
    requests_mock.delete(f"{NAMESPACE}/search/jobs/sid-1", json={})


def test_spl_string_escapes_quotes_and_backslashes():
    assert spl_string('a"b\\c') == '"a\\"b\\\\c"'


def test_build_ioc_lookup_attributes_each_value_as_a_whole_token():
    batch = IocBatch(
        "IPv4-Addr",
        None,
        (
            HuntIoc(key="k1", observable_type="IPv4-Addr", value="198.51.100.7"),
            HuntIoc(key="k2", observable_type="IPv4-Addr", value="198.51.100.8"),
        ),
    )
    query = build_ioc_lookup(batch)
    assert query.startswith('("198.51.100.7" OR "198.51.100.8") | eval ioc=mvappend(')
    assert '"k1"' in query and '"k2"' in query
    assert "| stats count as hits min(_time) as first_seen" in query
    assert "values(host) as hosts by ioc" in query
    # The attribution regex of a value never matches inside a longer address
    pattern = re.search(r'match\(_raw, "(\(\?i\)[^"]+)"\), "k1"', query).group(1)
    regex = re.compile(pattern.replace("\\\\", "\\"))
    assert regex.search("dst=198.51.100.7 port=443")
    assert not regex.search("dst=198.51.100.70")


def test_registers_indicator_lookups(connector_factory):
    connector = connector_factory()
    assert connector.supports_indicators is True
    assert connector.ioc_aggregated is True


def test_runs_one_aggregated_lookup_per_type_and_reports_each_value(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given Splunk aggregating the hits of one address of the batch
    _mock_job(
        requests_mock,
        [
            {
                "ioc": "k-ip",
                "hits": "14",
                "first_seen": "1759478400",
                "last_seen": "1759482000",
                "hosts": ["ws1", "ws2"],
            }
        ],
    )

    # When the indicator hunt run is processed
    message = connector_factory().process_message(_indicator_event(hunt_event))

    # Then one search runs per observable type, and every value is reported
    searches = [
        request for request in requests_mock.request_history if request.method == "POST"
    ]
    assert len(searches) == 2
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    by_key = {item["key"]: item for item in kwargs["ioc_results"]}
    assert by_key["k-ip"]["seen"] is True and by_key["k-ip"]["hits_count"] == 14
    assert by_key["k-ip"]["hosts"] == ["ws1", "ws2"]
    assert by_key["k-ip-2"]["seen"] is False
    assert kwargs["hits_count"] == 14
    assert kwargs["query_language"] == "spl"
    # Nothing is sent: OpenCTI sights the indicator of the address on the Security
    # Platform itself; aggregated counts carry no hit key, the hits count as new
    helper.send_stix2_bundle.assert_not_called()
    assert "hit_keys" not in kwargs
    assert by_key["k-ip"]["hit_keys"] is None
    assert "1 of 3 value(s) seen" in message


def test_previews_the_lookups(connector_factory, helper, requests_mock, hunt_event):
    connector_factory().process_message(_indicator_event(hunt_event, mode="preview"))
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["translated_query"].count("| stats count as hits") == 2
    assert '\\"b' in kwargs["translated_query"]
