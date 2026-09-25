"""Integration-style smoke tests for the Zetalytics DNS connector."""

import os
from typing import Any
from unittest.mock import MagicMock

from pycti import OpenCTIConnectorHelper
from zetalytics_dns.connector import Connector
from zetalytics_dns.settings import ConfigLoader


def make_stub_config(stub_config_dict: dict[str, Any]) -> ConfigLoader:
    """Return a ConfigLoader instance backed by stub_config_dict.

    Uses a closure so Pydantic never sees the dict as a private model field.
    """

    class _Stub(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:  # type: ignore[override]
            return handler(stub_config_dict)

    return _Stub()  # type: ignore[call-arg]


def test_config_loader_instantiates(stub_config_dict):
    """ConfigLoader should load successfully from a valid config dict."""
    config = make_stub_config(stub_config_dict)

    assert config.zetalytics.mode == "manual"
    assert config.zetalytics.max_results == 100
    assert config.zetalytics.include_live_dns is True
    assert config.zetalytics.include_subdomains is True
    assert config.zetalytics.include_historical_whois is False


def test_config_loader_to_helper_config(stub_config_dict):
    """to_helper_config() must return a dict compatible with OpenCTIConnectorHelper."""
    config = make_stub_config(stub_config_dict)
    helper_config = config.to_helper_config()

    assert isinstance(helper_config, dict)
    assert helper_config["opencti"]["url"] == "http://localhost:8080/"


def test_opencti_helper_instantiates(mock_opencti_helper, stub_config_dict):
    """OpenCTIConnectorHelper should initialise from the settings dict."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    # lookback_days=90 in stub_config_dict -> "3 months" is appended to the connector name.
    assert helper.connect_name == "Zetalytics DNS - Test (3 months)"


def test_connector_instantiates(mock_opencti_helper, stub_config_dict):
    """Connector should initialise and expose config and helper."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    assert connector.config is config
    assert connector.helper is helper
    assert connector.client is mock_client


def test_connector_skips_high_tlp(mock_opencti_helper, stub_config_dict):
    """process_message should skip enrichment when the observable TLP is too high,
    but still forward the original bundle unchanged for playbook compatibility."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=False)
    helper.connector_logger = MagicMock()
    helper.connector_logger.info = MagicMock(return_value="skipped")
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    original_objects = [{"type": "domain-name", "id": "domain-name--original"}]
    data = {
        "enrichment_entity": {
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
        },
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000001",
        },
        "stix_objects": original_objects,
    }

    connector.process_message(data)
    mock_client.passive_dns_for_domain.assert_not_called()
    helper.stix2_create_bundle.assert_called_once_with(original_objects)


def test_connector_skips_unsupported_type(mock_opencti_helper, stub_config_dict):
    """process_message should skip enrichment for unsupported observable types,
    but still forward the original bundle unchanged for playbook compatibility."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.connector_logger.info = MagicMock(return_value="skipped")
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    original_objects = [{"type": "url", "id": "url--original"}]
    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "url",
            "value": "https://example.com",
            "id": "url--00000000-0000-4000-8000-000000000002",
        },
        "stix_objects": original_objects,
    }

    connector.process_message(data)
    mock_client.passive_dns_for_domain.assert_not_called()
    mock_client.passive_dns_for_ip.assert_not_called()
    helper.stix2_create_bundle.assert_called_once_with(original_objects)


def test_connector_skips_type_outside_configured_scope(
    mock_opencti_helper, stub_config_dict
):
    """A type the connector can technically handle, but that has been excluded
    from this deployment's own CONNECTOR_SCOPE, must still be skipped -- while
    still forwarding the original bundle unchanged for playbook compatibility."""
    stub_config_dict["connector"]["scope"] = "Domain-Name,Hostname"
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.connector_logger.info = MagicMock(return_value="skipped")
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    original_objects = [{"type": "ipv4-addr", "id": "ipv4-addr--original"}]
    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "ipv4-addr",
            "value": "1.2.3.4",
            "id": "ipv4-addr--00000000-0000-4000-8000-000000000003",
        },
        "stix_objects": original_objects,
    }

    connector.process_message(data)
    mock_client.passive_dns_for_ip.assert_not_called()
    helper.stix2_create_bundle.assert_called_once_with(original_objects)


def test_ns2domain_pivot_only_follows_actual_nameservers(
    mock_opencti_helper, stub_config_dict
):
    """The ns2domain pivot must only fire for genuine NS records, not every
    domain-name discovered during enrichment (e.g. CNAME targets)."""
    stub_config_dict["zetalytics"]["include_ns2domain"] = True
    stub_config_dict["zetalytics"]["max_ns_pivot_results"] = 50
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_domain.return_value = {
        "results": [
            {"qname": "example.com", "rrtype": "ns", "value": "ns1.example.com"},
            {"qname": "example.com", "rrtype": "cname", "value": "alias.example.com"},
        ]
    }
    mock_client.ns_to_domains.return_value = {"results": []}
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000004",
        },
        "stix_objects": [],
    }
    connector.process_message(data)

    mock_client.ns_to_domains.assert_called_once()
    assert mock_client.ns_to_domains.call_args.args[0] == "ns1.example.com"


def test_mx2domain_pivot_follows_mx_hosts(mock_opencti_helper, stub_config_dict):
    """The mx2domain pivot should query mx_to_domains for each MX host found."""
    stub_config_dict["zetalytics"]["include_mx2domain"] = True
    stub_config_dict["zetalytics"]["max_mx_pivot_results"] = 50
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_domain.return_value = {
        "results": [
            {"qname": "example.com", "rrtype": "mx", "value": "10 mail.example.com"},
        ]
    }
    mock_client.mx_to_domains.return_value = {"results": []}
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000005",
        },
        "stix_objects": [],
    }
    connector.process_message(data)

    mock_client.mx_to_domains.assert_called_once()
    assert mock_client.mx_to_domains.call_args.args[0] == "mail.example.com"


def test_process_message_ip_happy_path(mock_opencti_helper, stub_config_dict):
    """process_message should route IP observables through _enrich_ip and send a bundle."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_ip.return_value = {
        "results": [{"qname": "example.com", "rrtype": "a", "value": "1.2.3.4"}]
    }
    mock_client.ip_context.return_value = {"results": []}
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "ipv4-addr",
            "value": "1.2.3.4",
            "id": "ipv4-addr--00000000-0000-4000-8000-000000000006",
        },
        "stix_objects": [],
    }
    result = connector.process_message(data)

    mock_client.passive_dns_for_ip.assert_called_once()
    mock_client.ip_context.assert_called_once()
    assert "1 bundle(s) sent" in result


def test_process_message_sends_anchor_bundle_without_results(
    mock_opencti_helper, stub_config_dict
):
    """When no enrichment data is found and create_note_when_no_results is off,
    the connector should still send the author + anchor observable (so
    Zetalytics is registered as having reviewed the entity, and playbook
    chains downstream still receive the entity) without adding a Note."""
    stub_config_dict["zetalytics"]["include_live_dns"] = False
    stub_config_dict["zetalytics"]["include_subdomains"] = False
    stub_config_dict["zetalytics"]["include_d8s"] = False
    stub_config_dict["zetalytics"]["include_ns_glue"] = False
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_domain.return_value = {"results": []}
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000007",
        },
        "stix_objects": [],
    }
    result = connector.process_message(data)

    assert "bundle(s) sent" in result
    sent_objects = helper.stix2_create_bundle.call_args.args[0]
    assert not any(o.get("type") == "note" for o in sent_objects)
    assert any(o.get("type") == "identity" for o in sent_objects)


def test_process_message_creates_note_when_no_results(
    mock_opencti_helper, stub_config_dict
):
    """When create_note_when_no_results is on, an explanatory Note should be sent instead."""
    stub_config_dict["zetalytics"]["include_live_dns"] = False
    stub_config_dict["zetalytics"]["include_subdomains"] = False
    stub_config_dict["zetalytics"]["include_d8s"] = False
    stub_config_dict["zetalytics"]["include_ns_glue"] = False
    stub_config_dict["zetalytics"]["create_note_when_no_results"] = True
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_domain.return_value = {"results": []}
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000008",
        },
        "stix_objects": [],
    }
    result = connector.process_message(data)

    assert "bundle(s) sent" in result
    sent_objects = helper.stix2_create_bundle.call_args.args[0]
    assert any(o.get("type") == "note" for o in sent_objects)


def test_enrich_domain_survives_every_endpoint_failing(
    mock_opencti_helper, stub_config_dict
):
    """A failure in any single Zetalytics endpoint must not abort enrichment as a
    whole -- each is caught, logged, and the connector moves on to the rest."""
    stub_config_dict["zetalytics"]["include_historical_whois"] = True
    stub_config_dict["zetalytics"]["max_whois_results"] = 5
    stub_config_dict["zetalytics"]["include_ns2domain"] = True
    stub_config_dict["zetalytics"]["include_mx2domain"] = True
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_domain.side_effect = RuntimeError("domain2rrtypes down")
    mock_client.live_dns.side_effect = RuntimeError("liveDNS down")
    mock_client.subdomains.side_effect = RuntimeError("subdomains down")
    mock_client.domain_d8s.side_effect = RuntimeError("d8s down")
    mock_client.domain_ns_glue.side_effect = RuntimeError("nsglue down")
    mock_client.domain_whois.side_effect = RuntimeError("whois down")
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000009",
        },
        "stix_objects": [],
    }
    result = connector.process_message(data)

    # process_message's own try/except only catches TlpError/UnsupportedEntityTypeError
    # specially; anything else still resolves to a result string, not a raised exception.
    assert result != "Error"
    assert helper.connector_logger.warning.call_count >= 6
    # No NS/MX records were discovered (passive DNS and ns_glue both failed), so
    # the pivots have nothing to iterate over and should not call out at all.
    mock_client.ns_to_domains.assert_not_called()
    mock_client.mx_to_domains.assert_not_called()


def test_pivots_survive_their_own_endpoint_failing(
    mock_opencti_helper, stub_config_dict
):
    """ns2domain/mx2domain pivot failures must be caught individually, per
    nameserver/MX host, rather than aborting the whole pivot pass."""
    stub_config_dict["zetalytics"]["include_ns2domain"] = True
    stub_config_dict["zetalytics"]["include_mx2domain"] = True
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_domain.return_value = {
        "results": [
            {"qname": "example.com", "rrtype": "ns", "value": "ns1.example.com"},
            {"qname": "example.com", "rrtype": "mx", "value": "10 mail.example.com"},
        ]
    }
    mock_client.ns_to_domains.side_effect = RuntimeError("ns2domain down")
    mock_client.mx_to_domains.side_effect = RuntimeError("mx2domain down")
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000011",
        },
        "stix_objects": [],
    }
    result = connector.process_message(data)

    assert result != "Error"
    mock_client.ns_to_domains.assert_called_once()
    mock_client.mx_to_domains.assert_called_once()


def test_process_message_forwards_original_bundle_on_unexpected_error(
    mock_opencti_helper, stub_config_dict
):
    """An unexpected exception outside the TLP/scope guards (e.g. malformed
    input data) must still forward the original bundle unchanged, the same
    playbook-compatibility guarantee as the TLP/scope skip paths."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    original_objects = [{"type": "domain-name", "id": "domain-name--original"}]
    data = {
        "enrichment_entity": {"objectMarking": []},
        # Missing "id" raises a KeyError when read, escaping to the outer
        # generic Exception handler.
        "stix_entity": {"type": "domain-name", "value": "example.com"},
        "stix_objects": original_objects,
    }
    result = connector.process_message(data)

    assert result != "Error"
    mock_client.passive_dns_for_domain.assert_not_called()
    helper.stix2_create_bundle.assert_called_once_with(original_objects)


def test_enrich_ip_survives_every_endpoint_failing(
    mock_opencti_helper, stub_config_dict
):
    """Same resilience guarantee as domains, for the IP enrichment path."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.stix2_create_bundle = MagicMock(
        return_value={"type": "bundle", "objects": []}
    )
    helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])

    mock_client = MagicMock()
    mock_client.passive_dns_for_ip.side_effect = RuntimeError("ip down")
    mock_client.ip_context.side_effect = RuntimeError("ip2pwhois down")
    mock_client.ip_ns_glue.side_effect = RuntimeError("ip2nsglue down")
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "ipv4-addr",
            "value": "1.2.3.4",
            "id": "ipv4-addr--00000000-0000-4000-8000-000000000010",
        },
        "stix_objects": [],
    }
    result = connector.process_message(data)

    assert result != "Error"
    assert helper.connector_logger.warning.call_count >= 3


def test_send_bundle_reports_no_bundle_produced(mock_opencti_helper, stub_config_dict):
    """_send_bundle should short-circuit cleanly when the helper produces no bundle."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.stix2_create_bundle = MagicMock(return_value=None)
    helper.send_stix2_bundle = MagicMock()

    connector = Connector(config=config, helper=helper, client=MagicMock())
    result = connector._send_bundle([])

    assert result == "No STIX bundle produced"
    helper.send_stix2_bundle.assert_not_called()


def test_main_syncs_connector_name_env_var_before_helper_init(monkeypatch):
    """main() must sync CONNECTOR_NAME in the environment to the lookback-suffixed name.

    pycti's get_config_variable() checks the raw environment variable *before* the
    config dict passed to OpenCTIConnectorHelper, so without this sync it would
    silently ignore ConfigLoader's suffixed name (e.g. "... (2 years)") and register
    the connector in OpenCTI using whatever CONNECTOR_NAME is set to in the
    environment/compose file.
    """
    monkeypatch.setenv("CONNECTOR_NAME", "Zetalytics DNS - Deep Investigation")

    fake_config = MagicMock()
    fake_config.connector.name = "Zetalytics DNS - Deep Investigation (2 years)"
    fake_config.to_helper_config.return_value = {
        "connector": {"name": fake_config.connector.name}
    }
    fake_config.zetalytics.token.get_secret_value.return_value = "zt-token"
    fake_config.zetalytics.request_timeout = 30

    mock_config_loader_cls = MagicMock(return_value=fake_config)
    mock_helper_cls = MagicMock()
    mock_client_cls = MagicMock()
    mock_connector_cls = MagicMock()

    monkeypatch.setattr("zetalytics_dns.settings.ConfigLoader", mock_config_loader_cls)
    monkeypatch.setattr("pycti.OpenCTIConnectorHelper", mock_helper_cls)
    monkeypatch.setattr("zetalytics_dns.client.ZetalyticsClient", mock_client_cls)
    monkeypatch.setattr("zetalytics_dns.connector.Connector", mock_connector_cls)

    from zetalytics_dns.__main__ import main

    main()

    assert (
        os.environ["CONNECTOR_NAME"] == "Zetalytics DNS - Deep Investigation (2 years)"
    )
    _, helper_kwargs = mock_helper_cls.call_args
    assert (
        helper_kwargs["config"]["connector"]["name"]
        == "Zetalytics DNS - Deep Investigation (2 years)"
    )
    mock_connector_cls.return_value.run.assert_called_once()
