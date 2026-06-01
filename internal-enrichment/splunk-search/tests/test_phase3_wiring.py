import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import stix2
from internal_enrichment_connector.cim_parser import ParsedObservable
from internal_enrichment_connector.connector import SplunkSearchConnector
from internal_enrichment_connector.ua_parser import ParsedUserAgent


def _helper():
    helper = Mock()
    helper.api.indicator.list.return_value = []
    helper.api.note.list.return_value = []
    helper.send_stix2_bundle.return_value = ["bundle-id"]
    helper.connector_logger = Mock()
    helper.connector_logger.debug = Mock()
    helper.connector_logger.info = Mock()
    helper.connector_logger.error = Mock()
    helper.connector_logger.warning = Mock()
    return helper


def _config():
    return SimpleNamespace(
        splunk_host="splunk.example.com",
        splunk_port=8089,
        splunk_token="token",
        splunk_app="search",
        splunk_scheme="https",
        splunk_verify_ssl=True,
        splunk_search_earliest="-30d@d",
        splunk_search_latest="now",
        splunk_timeout=60,
        splunk_wait_seconds=2,
        splunk_max_results=1000,
        observable_tlp="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        sighting_tlp="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    )


def _connector(helper=None):
    with patch("internal_enrichment_connector.connector.SplunkClient"):
        return SplunkSearchConnector(helper=helper or _helper(), config=_config())


def _template():
    return {
        "id": "indicator--00000000-0000-4000-8000-000000000301",
        "x_opencti_id": "template-opencti-id",
        "name": "IP Search",
        "pattern_type": "spl",
        "pattern": "index=main src IN (<IP_LIST>)",
        "x_opencti_main_observable_type": "IPv4-Addr",
    }


def _entity():
    return {
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "x_opencti_main_observable_type": "IPv4-Addr",
    }


def _stix_objects():
    return [
        {
            "type": "ipv4-addr",
            "id": "ipv4-addr--11111111-2222-4333-8444-555555555555",
            "value": "1.2.3.4",
        }
    ]


def _run_enrichment(connector):
    connector.splunk_client.run_search.return_value = [
        {"sourcetype": "test", "src": "1.2.3.4", "http_user_agent": "curl/8.7.1"}
    ]
    connector.helper.api.indicator.list.return_value = [_template()]
    return connector._enrich_stix_indicator(_entity(), _stix_objects(), "IPv4-Addr")


def test_cim_parser_wired():
    connector = _connector()
    connector.cim_parser.parse_results = Mock(return_value=[])

    _run_enrichment(connector)

    connector.cim_parser.parse_results.assert_called_once()
    assert connector.cim_parser.parse_results.call_args.args[0] == [
        {"sourcetype": "test", "src": "1.2.3.4", "http_user_agent": "curl/8.7.1"}
    ]


def test_ua_parser_wired():
    helper = _helper()
    connector = _connector(helper)
    connector.cim_parser.parse_results = Mock(
        return_value=[
            ParsedObservable(
                stix_type="User-Agent",
                stix_property="value",
                value="curl/8.7.1",
                source_field="http_user_agent",
            )
        ]
    )
    connector.ua_parser.parse = Mock(
        return_value=ParsedUserAgent(
            software_name="curl",
            software_version="8.7.1",
            os_name=None,
            os_version=None,
            device_type=None,
            raw_string="curl/8.7.1",
            vendor="curl",
        )
    )

    _run_enrichment(connector)

    connector.ua_parser.parse.assert_called_once_with("curl/8.7.1")

    serialized = helper.send_stix2_bundle.call_args.args[0]
    bundle = json.loads(serialized)
    software_objects = [
        obj for obj in bundle["objects"] if obj.get("type") == "software"
    ]
    relationships = [
        obj
        for obj in bundle["objects"]
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "related-to"
    ]

    assert software_objects
    assert relationships
    assert (
        relationships[0]["target_ref"]
        == "ipv4-addr--11111111-2222-4333-8444-555555555555"
    )


def test_ua_parser_skipped_when_no_ua():
    connector = _connector()
    connector.cim_parser.parse_results = Mock(
        return_value=[
            ParsedObservable(
                stix_type="IPv4-Addr",
                stix_property="value",
                value="1.2.3.4",
                source_field="src_ip",
            )
        ]
    )
    connector.ua_parser.parse = Mock(wraps=connector.ua_parser.parse)

    _run_enrichment(connector)

    connector.ua_parser.parse.assert_not_called()


def test_enrichment_still_works_without_cim_fields():
    helper = _helper()
    connector = _connector(helper)
    connector.cim_parser.parse_results = Mock(return_value=[])

    message = _run_enrichment(connector)

    assert message.startswith("Ran 1 searches, 1 rows")
    serialized = helper.send_stix2_bundle.call_args.args[0]
    bundle = json.loads(serialized)
    assert any(obj.get("type") == "sighting" for obj in bundle["objects"])


def test_software_idempotency():
    connector = _connector()
    rows = [{"http_user_agent": "curl/8.7.1"}]

    target_ref = "ipv4-addr--11111111-2222-4333-8444-555555555555"
    objects_one = connector._build_ua_software_objects(rows, [target_ref])
    objects_two = connector._build_ua_software_objects(rows, [target_ref])

    software_one = [obj for obj in objects_one if isinstance(obj, stix2.Software)][0]
    software_two = [obj for obj in objects_two if isinstance(obj, stix2.Software)][0]
    assert software_one.id == software_two.id
