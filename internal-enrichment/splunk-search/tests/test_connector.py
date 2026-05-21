from types import SimpleNamespace
from unittest.mock import Mock, patch

import stix2
from internal_enrichment_connector.connector import (
    SPLUNK_TEMPLATE_LABEL,
    SplunkSearchConnector,
)


def _helper(existing_indicators=None):
    helper = Mock()
    helper.api.indicator.list.return_value = existing_indicators or []
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


def test_seed_default_searches_when_missing():
    connector = _connector(_helper())

    connector._seed_default_searches()

    connector.helper.api.indicator.list.assert_called_once()
    filters = connector.helper.api.indicator.list.call_args.kwargs["filters"]
    assert filters["filters"][0]["values"] == ["spl"]
    assert filters["filters"][1]["values"] == [SPLUNK_TEMPLATE_LABEL]
    connector.helper.send_stix2_bundle.assert_called_once()
    serialized = connector.helper.send_stix2_bundle.call_args.args[0]
    assert '"type": "bundle"' in serialized
    assert SPLUNK_TEMPLATE_LABEL in serialized
    assert connector.helper.send_stix2_bundle.call_args.kwargs["update"] is True


def test_seed_default_searches_skips_when_present():
    connector = _connector(_helper(existing_indicators=[{"id": "indicator--1"}]))

    connector._seed_default_searches()

    connector.helper.send_stix2_bundle.assert_not_called()


def test_get_search_templates_uses_required_filters():
    connector = _connector()

    connector._get_search_templates("IPv4-Addr")

    filters = connector.helper.api.indicator.list.call_args.kwargs["filters"]
    assert filters["mode"] == "and"
    assert filters["filters"] == [
        {"key": "pattern_type", "values": ["spl"], "operator": "eq"},
        {"key": "objectLabel", "values": [SPLUNK_TEMPLATE_LABEL], "operator": "eq"},
        {
            "key": "x_opencti_main_observable_type",
            "values": ["IPv4-Addr"],
            "operator": "eq",
        },
    ]


def test_extract_observable_values_from_stix_objects():
    connector = _connector()

    assert connector._extract_observable_values(
        {}, [{"type": "ipv4-addr", "value": "1.2.3.4"}], "IPv4-Addr"
    ) == ["1.2.3.4"]
    assert connector._extract_observable_values(
        {}, [{"type": "domain-name", "value": "example.com"}], "Domain-Name"
    ) == ["example.com"]
    assert connector._extract_observable_values(
        {}, [{"type": "x-opencti-hostname", "value": "host1"}], "Hostname"
    ) == ["host1"]
    assert connector._extract_observable_values(
        {}, [{"type": "url", "value": "https://example.com"}], "Url"
    ) == ["https://example.com"]
    assert connector._extract_observable_values(
        {}, [{"type": "email-addr", "value": "a@example.com"}], "Email-Addr"
    ) == ["a@example.com"]
    assert connector._extract_observable_values(
        {},
        [{"type": "file", "hashes": {"MD5": "a" * 32, "SHA-256": "b" * 64}}],
        "StixFile",
    ) == ["b" * 64, "a" * 32]


def test_extract_observable_values_falls_back_to_stix_pattern():
    connector = _connector()

    values = connector._extract_observable_values(
        {
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        },
        [],
        "IPv4-Addr",
    )

    assert values == ["1.2.3.4"]


def test_enrich_stix_indicator_runs_templates_and_sends_bundle():
    helper = _helper()
    connector = _connector(helper)
    connector.splunk_client.run_search.return_value = [
        {"sourcetype": "test", "src": "1.2.3.4"}
    ]
    template = {
        "id": "indicator--00000000-0000-4000-8000-000000000001",
        "x_opencti_id": "template-opencti-id",
        "name": "IP Search",
        "pattern_type": "spl",
        "pattern": "index=main src IN (<IP_LIST>)",
        "x_opencti_main_observable_type": "IPv4-Addr",
    }
    helper.api.indicator.list.return_value = [template]

    message = connector._enrich_stix_indicator(
        {
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "x_opencti_main_observable_type": "IPv4-Addr",
        },
        [],
        "IPv4-Addr",
    )

    assert message.startswith("Ran 1 searches, 1 results")
    connector.splunk_client.run_search.assert_called_once()
    assert '"type": "bundle"' in helper.send_stix2_bundle.call_args.args[0]


def test_note_search_params_override_config_defaults():
    helper = _helper()
    helper.api.note.list.return_value = [
        {"content": '{"earliest_time": "-90d@d", "timeout": 120, "max_results": 50}'}
    ]
    connector = _connector(helper)
    template = {
        "id": "indicator--00000000-0000-4000-8000-000000000003",
        "x_opencti_id": "template-opencti-id",
        "name": "IP Search",
        "pattern_type": "spl",
        "pattern": "index=main src IN (<IP_LIST>)",
        "x_opencti_main_observable_type": "IPv4-Addr",
    }

    connector._run_search_for_indicator(template, "IPv4-Addr", ["1.2.3.4"])

    connector.splunk_client.run_search.assert_called_once_with(
        query='index=main src IN ("1.2.3.4")',
        earliest_time="-90d@d",
        latest_time="now",
        timeout=120,
        wait_seconds=2,
        max_results=50,
    )


def test_enrich_spl_indicator_runs_direct_search_and_sends_bundle():
    connector = _connector()
    connector.splunk_client.run_search.return_value = [
        {"sourcetype": "test", "src": "1.2.3.4"}
    ]
    entity = {
        "id": "indicator--00000000-0000-4000-8000-000000000002",
        "x_opencti_id": "direct-opencti-id",
        "name": "Direct Search",
        "pattern_type": "spl",
        "pattern": "index=main | head 1",
    }

    message = connector._enrich_spl_indicator(entity, [], "")

    assert message.startswith("SPL direct: 1 results")
    connector.splunk_client.run_search.assert_called_once()
    connector.helper.send_stix2_bundle.assert_called_once()


def test_process_message_skips_unsupported_pattern_type():
    connector = _connector()

    message = connector._process_message(
        {"enrichment_entity": {"pattern_type": "yara"}, "stix_objects": []}
    )

    assert message == "Unsupported pattern_type 'yara', skipping"
    connector.helper.connector_logger.warning.assert_called_once()


def test_author_identity_loaded_from_seed_bundle():
    connector = _connector()

    assert isinstance(connector.author, stix2.Identity)
    assert connector.author.name == "Splunk"
