"""Flow tests: the SDK `InternalEnrichmentConnector` driving `AlienVaultOtxProcessor`.

Everything is mocked: the helper (no OpenCTI), and there is no OTX client yet.
"""

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector import AlienVaultOtxProcessor, ConnectorSettings
from connectors_sdk import ConfigValidationError, InternalEnrichmentConnector
from pycti import OpenCTIConnectorHelper

PATCH_HELPER = "connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector.OpenCTIConnectorHelper"

OCTI_ID = "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c"
IP_ID = "ipv4-addr--0b7e1c5a-3f2d-5e6a-9b8c-1d2e3f4a5b6c"
DOMAIN_ID = "domain-name--3c6b8a4e-1a52-5c1b-9b7e-3f3c3c7f4b6e"
URL_ID = "url--1f9e1b2e-1c3b-5b5e-8f4a-2b8f0f9e8d7c"
IPV6_ID = "ipv6-addr--2a9e1b2e-1c3b-5b5e-8f4a-2b8f0f9e8d7d"
RELATED_ID = "x-opencti-text--0a2c6d1e-3f5b-5d7a-9c1e-4b6d8f0a2c4e"


def _make_settings(connector: dict[str, Any] | None = None) -> ConnectorSettings:
    """Build real settings, with the given `connector` section over the defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": connector or {},
                    "alienvault_otx": {"api_key": "test-api-key"},
                }
            )

    return FakeConnectorSettings()


def _make_helper(playbook: bool = False) -> MagicMock:
    helper = MagicMock()
    helper.playbook = {"playbook_id": "playbook--1"} if playbook else None
    helper.stix2_create_bundle.side_effect = OpenCTIConnectorHelper.stix2_create_bundle
    helper.send_stix2_bundle.return_value = ["bundle"]
    return helper


def _make_connector(
    helper: MagicMock, settings: ConnectorSettings | None = None
) -> tuple[InternalEnrichmentConnector, AlienVaultOtxProcessor]:
    processor = AlienVaultOtxProcessor()
    # Spy on the placeholder: it stands for the future OTX call
    processor.collect = MagicMock(wraps=processor.collect)
    connector = InternalEnrichmentConnector(
        settings=settings or _make_settings(),
        enrichment_processors=[processor],
    )
    with patch(PATCH_HELPER, return_value=helper):
        connector._init_dependencies()
    return connector, processor


ENTITIES = {
    "IPv4-Addr": {"type": "ipv4-addr", "id": IP_ID, "value": "1.2.3.4"},
    "Domain-Name": {"type": "domain-name", "id": DOMAIN_ID, "value": "example.com"},
    "Url": {"type": "url", "id": URL_ID, "value": "https://example.com/a"},
    "IPv6-Addr": {"type": "ipv6-addr", "id": IPV6_ID, "value": "2001:db8::1"},
}


def _make_data(
    entity_type: str = "IPv4-Addr", tlp: str | None = None, playbook: bool = False
) -> dict[str, Any]:
    stix_entity = {
        **ENTITIES[entity_type],
        "spec_version": "2.1",
        "object_marking_refs": ["marking-definition--original"],
    }
    related = {"type": "x-opencti-text", "id": RELATED_ID, "value": "t"}
    object_marking = (
        [{"definition_type": "TLP", "definition": tlp}] if tlp is not None else []
    )
    data = {
        "entity_id": stix_entity["id"],
        "enrichment_entity": {
            "id": OCTI_ID,
            "entity_type": entity_type,
            "objectMarking": object_marking,
        },
        "stix_entity": stix_entity,
        "stix_objects": [dict(stix_entity), related],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
        data["entity_type"] = entity_type
    return data


def _sent_objects(helper: MagicMock) -> list[dict[str, Any]]:
    bundle = helper.send_stix2_bundle.call_args_list[0].args[0]
    return json.loads(bundle)["objects"]


class TestBuild:
    def test_builds_with_the_default_scope(self):
        connector, processor = _make_connector(_make_helper())

        assert connector.enrichment_processors == [processor]
        assert connector._enabled_entity_types == ["IPv4-Addr"]

    def test_creates_a_playbook_compatible_helper(self):
        connector = InternalEnrichmentConnector(
            settings=_make_settings(), enrichment_processors=[AlienVaultOtxProcessor()]
        )

        with patch(PATCH_HELPER, return_value=_make_helper()) as helper_cls:
            connector._init_dependencies()

        assert helper_cls.call_args.kwargs["playbook_compatible"] is True

    def test_injects_the_settings_into_the_processor(self):
        settings = _make_settings()

        _, processor = _make_connector(_make_helper(), settings=settings)

        assert processor.settings is settings

    def test_accepts_every_handled_entity_type_in_scope(self):
        settings = _make_settings({"scope": "IPv4-Addr,Domain-Name,Url"})

        connector, _ = _make_connector(_make_helper(), settings=settings)

        assert connector._enabled_entity_types == ["IPv4-Addr", "Domain-Name", "Url"]

    def test_rejects_a_scope_type_the_processor_does_not_handle(self):
        settings = _make_settings({"scope": "IPv4-Addr,StixFile"})

        with pytest.raises(ConfigValidationError, match="StixFile"):
            InternalEnrichmentConnector(
                settings=settings, enrichment_processors=[AlienVaultOtxProcessor()]
            )

    def test_start_listens_with_the_callback(self):
        helper = _make_helper()
        connector = InternalEnrichmentConnector(
            settings=_make_settings(), enrichment_processors=[AlienVaultOtxProcessor()]
        )

        with patch(PATCH_HELPER, return_value=helper):
            connector.start()

        helper.listen.assert_called_once_with(message_callback=connector.callback)


class TestInScope:
    @pytest.mark.parametrize("entity_type", ["IPv4-Addr", "Domain-Name", "Url"])
    def test_manual_in_scope_calls_the_placeholder_and_sends_nothing(self, entity_type):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings({"scope": "IPv4-Addr,Domain-Name,Url"})
        )

        result = connector.callback(_make_data(entity_type))

        assert result == "No enrichment data found"
        processor.collect.assert_called_once()
        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_in_scope_sends_the_original_bundle_once(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)
        data = _make_data(playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.collect.assert_called_once()
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    @pytest.mark.parametrize("tlp", [None, "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"])
    def test_entities_up_to_max_tlp_reach_the_processor(self, tlp):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        connector.callback(_make_data(tlp=tlp))

        processor.collect.assert_called_once()

    def test_entity_without_tlp_reaches_the_processor_after_a_marked_one(self):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        connector.callback(_make_data(tlp="TLP:AMBER"))
        connector.callback(_make_data(tlp=None))

        assert processor.collect.call_count == 2


class TestOutOfScope:
    @pytest.mark.parametrize("entity_type", ["Domain-Name", "Url", "IPv6-Addr"])
    def test_manual_out_of_scope_never_reaches_the_processor(self, entity_type):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        result = connector.callback(_make_data(entity_type))

        assert result == f"Entity type {entity_type} is out of scope"
        processor.collect.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()

    @pytest.mark.parametrize("entity_type", ["Domain-Name", "Url", "IPv6-Addr"])
    def test_playbook_out_of_scope_sends_the_original_bundle_unchanged(
        self, entity_type
    ):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)
        data = _make_data(entity_type, playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.collect.assert_not_called()
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_scope_is_checked_before_tlp(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)

        result = connector.callback(
            _make_data("IPv6-Addr", tlp="TLP:RED", playbook=True)
        )

        assert result == "Entity type IPv6-Addr is out of scope"
        processor.collect.assert_not_called()


class TestMaxTlp:
    @pytest.mark.parametrize("tlp", ["TLP:RED", "TLP:AMBER+STRICT"])
    def test_manual_entity_above_max_tlp_never_reaches_the_processor(self, tlp):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        result = connector.callback(_make_data(tlp=tlp))

        assert result == "Entity TLP is not allowed (max TLP: amber)"
        processor.collect.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_entity_above_max_tlp_sends_the_original_bundle(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)
        data = _make_data(tlp="TLP:RED", playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.collect.assert_not_called()
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_a_lower_max_tlp_from_the_settings_is_applied(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings({"max_tlp": "TLP:GREEN"})
        )

        connector.callback(_make_data(tlp="TLP:AMBER"))

        processor.collect.assert_not_called()

    def test_a_higher_max_tlp_from_the_settings_is_applied(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings({"max_tlp": "TLP:RED"})
        )

        connector.callback(_make_data(tlp="TLP:RED"))

        processor.collect.assert_called_once()
