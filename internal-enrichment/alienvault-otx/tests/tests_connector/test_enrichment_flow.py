"""Flow tests: the SDK `InternalEnrichmentConnector` driving `AlienVaultOtxProcessor`.

Everything is mocked: the helper (no OpenCTI) and the OTX client (no network). The
entities have real deterministic STIX ids, so that the replacement of the entity by
the enriched observable is really tested.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connector import AlienVaultOtxProcessor, ConnectorSettings
from connectors_sdk import ConfigValidationError, InternalEnrichmentConnector
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import URL, DomainName, IPV4Address
from otx_client import OtxClient, OtxGeneral
from pycti import Identity, OpenCTIConnectorHelper

PATCH_HELPER = "connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector.OpenCTIConnectorHelper"

RESOURCES = Path(__file__).parent.parent / "resources"
KNOWN = OtxGeneral.model_validate_json(
    (RESOURCES / "general_ipv4_known.json").read_text()
)
UNKNOWN = OtxGeneral.model_validate_json(
    (RESOURCES / "general_ipv4_unknown.json").read_text()
)
DOMAIN_UNKNOWN = OtxGeneral.model_validate_json(
    (RESOURCES / "general_domain_unknown.json").read_text()
)
HOSTNAME_KNOWN = OtxGeneral.model_validate_json(
    (RESOURCES / "general_hostname_known.json").read_text()
)
DOMAIN_SCOPE = {"scope": "Domain-Name"}
HOSTNAME_REFERENCE_URL = (
    "https://otx.alienvault.com/indicator/hostname/malicious.example"
)

OCTI_ID = "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c"
RELATED_ID = "x-opencti-text--0a2c6d1e-3f5b-5d7a-9c1e-4b6d8f0a2c4e"
AUTHOR_ID = Identity.generate_id("AlienVault", "organization")
OTX_REFERENCE_URLS = {
    "IPv4-Addr": "https://otx.alienvault.com/indicator/ip/192.0.2.10",
    "Domain-Name": "https://otx.alienvault.com/indicator/domain/malicious.example",
    "Url": "https://otx.alienvault.com/indicator/url/"
    "http%3A%2F%2Fmalicious.example%2Fpayload.bin%3Fid%3D1",
}


def _entity(model: Any, stix_type: str, value: str) -> dict[str, str]:
    """An entity as sent by OpenCTI, with the deterministic id of its value."""
    return {
        "type": stix_type,
        "id": model(value=value).to_stix2_object().id,
        "value": value,
    }


ENTITIES = {
    "IPv4-Addr": _entity(IPV4Address, "ipv4-addr", "192.0.2.10"),
    "Domain-Name": _entity(DomainName, "domain-name", "malicious.example"),
    "Url": _entity(URL, "url", "http://malicious.example/payload.bin?id=1"),
    # Not handled by the connector: only its id matters
    "IPv6-Addr": {
        "type": "ipv6-addr",
        "id": "ipv6-addr--2a9e1b2e-1c3b-5b5e-8f4a-2b8f0f9e8d7d",
        "value": "2001:db8::1",
    },
}


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
    helper: MagicMock,
    settings: ConnectorSettings | None = None,
    general: OtxGeneral | None = KNOWN,
) -> tuple[InternalEnrichmentConnector, AlienVaultOtxProcessor]:
    """Build the connector, then replace the OTX client built in `post_init()`."""
    processor = AlienVaultOtxProcessor()
    connector = InternalEnrichmentConnector(
        settings=settings or _make_settings(),
        enrichment_processors=[processor],
    )
    with patch(PATCH_HELPER, return_value=helper):
        connector._init_dependencies()
    processor.client = MagicMock(spec=OtxClient)
    processor.client.get_general.return_value = general
    return connector, processor


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


def _dangling_references(objects: list[dict[str, Any]]) -> list[str]:
    """The `*_ref` and `*_refs` values of the objects that point outside the bundle."""
    ids = {obj["id"] for obj in objects}
    return [
        ref
        for obj in objects
        for key, value in obj.items()
        if key.endswith(("_ref", "_refs"))
        for ref in (value if isinstance(value, list) else [value])
        if ref not in ids
    ]


def _assert_enriched_bundle(
    helper: MagicMock,
    entity_type: str,
    original: list[dict[str, Any]],
    reference_url: str | None = None,
) -> None:
    """The bundle sent holds the author, the marking, the observable and its note."""
    objects = _sent_objects(helper)
    by_id = {obj["id"]: obj for obj in objects}
    entity_id = ENTITIES[entity_type]["id"]

    assert len(by_id) == len(objects)
    # The entity is replaced in place by the observable rebuilt from its value
    assert [obj["id"] for obj in objects[:2]] == [entity_id, RELATED_ID]
    assert by_id[RELATED_ID] == original[1]
    assert by_id[entity_id] != original[0]
    assert by_id[entity_id]["value"] == ENTITIES[entity_type]["value"]
    extension = next(iter(by_id[entity_id]["extensions"].values()))
    assert extension["external_references"] == [
        {
            "source_name": "AlienVault OTX",
            "url": reference_url or OTX_REFERENCE_URLS[entity_type],
        }
    ]
    # The author and the TLP:CLEAR marking come with it
    assert by_id[AUTHOR_ID]["name"] == "AlienVault"
    markings = [obj for obj in objects if obj["type"] == "marking-definition"]
    assert [marking["x_opencti_definition"] for marking in markings] == ["TLP:CLEAR"]
    # The note summarises the OTX answer and is attached to the entity only
    notes = [obj for obj in objects if obj["type"] == "note"]
    assert len(notes) == 1
    assert notes[0]["abstract"] == "AlienVault OTX Enrichment Results"
    assert notes[0]["content"].startswith("## General\n\n- **Type**: ")
    # Reputation and geolocation only for IPv4, even though these tests answer every
    # type with the IPv4 fixture
    is_ipv4 = entity_type == "IPv4-Addr"
    assert ("- **OTX reputation**: 0" in notes[0]["content"]) is is_ipv4
    assert ("## Geolocation" in notes[0]["content"]) is is_ipv4
    assert notes[0]["object_refs"] == [entity_id]
    assert notes[0]["created_by_ref"] == AUTHOR_ID
    assert notes[0]["object_marking_refs"] == [markings[0]["id"]]
    # The entity, the related object, the author, the marking and the note: no more
    assert len(objects) == 5
    assert _dangling_references(objects) == []


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
    def test_manual_known_indicator_sends_the_enriched_bundle_once(self, entity_type):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings({"scope": "IPv4-Addr,Domain-Name,Url"})
        )
        data = _make_data(entity_type)
        original = [dict(obj) for obj in data["stix_objects"]]

        result = connector.callback(data)

        assert result == "Entity enriched with 4 objects"
        processor.client.get_general.assert_called_once()
        helper.send_stix2_bundle.assert_called_once()
        _assert_enriched_bundle(helper, entity_type, original)

    @pytest.mark.parametrize("entity_type", ["IPv4-Addr", "Domain-Name", "Url"])
    def test_playbook_known_indicator_sends_the_enriched_bundle_once(self, entity_type):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(
            helper, _make_settings({"scope": "IPv4-Addr,Domain-Name,Url"})
        )
        data = _make_data(entity_type, playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.client.get_general.assert_called_once()
        helper.send_stix2_bundle.assert_called_once()
        _assert_enriched_bundle(helper, entity_type, original)

    @pytest.mark.parametrize("general", [None, UNKNOWN])
    def test_manual_without_data_sends_nothing(self, general):
        helper = _make_helper()
        connector, processor = _make_connector(helper, general=general)

        result = connector.callback(_make_data())

        assert result == "No enrichment data found"
        processor.client.get_general.assert_called_once()
        helper.send_stix2_bundle.assert_not_called()

    @pytest.mark.parametrize("general", [None, UNKNOWN])
    def test_playbook_without_data_sends_the_original_bundle_once(self, general):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper, general=general)
        data = _make_data(playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.client.get_general.assert_called_once()
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_manual_failure_is_raised_and_sends_nothing(self):
        helper = _make_helper()
        connector, processor = _make_connector(helper)
        processor.client.get_general.side_effect = DataRetrievalError("OTX is down")

        with pytest.raises(DataRetrievalError, match="OTX is down"):
            connector.callback(_make_data())

        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_failure_is_raised_and_sends_the_original_bundle_once(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)
        processor.client.get_general.side_effect = DataRetrievalError("OTX is down")
        data = _make_data(playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        with pytest.raises(DataRetrievalError, match="OTX is down"):
            connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    @pytest.mark.parametrize("tlp", [None, "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"])
    def test_entities_up_to_max_tlp_reach_the_processor(self, tlp):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        connector.callback(_make_data(tlp=tlp))

        processor.client.get_general.assert_called_once()

    def test_entity_without_tlp_reaches_the_processor_after_a_marked_one(self):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        connector.callback(_make_data(tlp="TLP:AMBER"))
        connector.callback(_make_data(tlp=None))

        assert processor.client.get_general.call_count == 2


class TestHostnameFallback:
    def test_manual_domain_known_through_hostname_links_to_the_hostname_page(self):
        helper = _make_helper()
        connector, processor = _make_connector(helper, _make_settings(DOMAIN_SCOPE))
        processor.client.get_general.side_effect = [DOMAIN_UNKNOWN, HOSTNAME_KNOWN]
        data = _make_data("Domain-Name")
        original = [dict(obj) for obj in data["stix_objects"]]

        result = connector.callback(data)

        assert result == "Entity enriched with 4 objects"
        assert [c.args for c in processor.client.get_general.call_args_list] == [
            ("domain", "malicious.example"),
            ("hostname", "malicious.example"),
        ]
        helper.send_stix2_bundle.assert_called_once()
        _assert_enriched_bundle(
            helper, "Domain-Name", original, reference_url=HOSTNAME_REFERENCE_URL
        )

    def test_playbook_domain_known_through_hostname_sends_the_enriched_bundle_once(
        self,
    ):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper, _make_settings(DOMAIN_SCOPE))
        processor.client.get_general.side_effect = [DOMAIN_UNKNOWN, HOSTNAME_KNOWN]
        data = _make_data("Domain-Name", playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        _assert_enriched_bundle(
            helper, "Domain-Name", original, reference_url=HOSTNAME_REFERENCE_URL
        )

    def test_known_domain_never_queries_hostname_and_links_to_the_domain_page(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings(DOMAIN_SCOPE), general=KNOWN
        )
        data = _make_data("Domain-Name")
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.client.get_general.assert_called_once()
        _assert_enriched_bundle(helper, "Domain-Name", original)

    def test_manual_domain_unknown_in_both_sections_sends_nothing(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings(DOMAIN_SCOPE), general=DOMAIN_UNKNOWN
        )

        result = connector.callback(_make_data("Domain-Name"))

        assert result == "No enrichment data found"
        assert processor.client.get_general.call_count == 2
        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_domain_unknown_in_both_sections_sends_the_original_once(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(
            helper, _make_settings(DOMAIN_SCOPE), general=DOMAIN_UNKNOWN
        )
        data = _make_data("Domain-Name", playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        assert processor.client.get_general.call_count == 2
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_domain_rejected_by_otx_never_queries_hostname(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings(DOMAIN_SCOPE), general=None
        )

        result = connector.callback(_make_data("Domain-Name"))

        assert result == "No enrichment data found"
        processor.client.get_general.assert_called_once()
        helper.send_stix2_bundle.assert_not_called()

    def test_manual_hostname_failure_is_raised_and_sends_nothing(self):
        helper = _make_helper()
        connector, processor = _make_connector(helper, _make_settings(DOMAIN_SCOPE))
        processor.client.get_general.side_effect = [
            DOMAIN_UNKNOWN,
            DataRetrievalError("OTX hostname is down"),
        ]

        with pytest.raises(DataRetrievalError, match="OTX hostname is down"):
            connector.callback(_make_data("Domain-Name"))

        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_hostname_failure_is_raised_and_sends_the_original_once(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper, _make_settings(DOMAIN_SCOPE))
        processor.client.get_general.side_effect = [
            DOMAIN_UNKNOWN,
            DataRetrievalError("OTX hostname is down"),
        ]
        data = _make_data("Domain-Name", playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        with pytest.raises(DataRetrievalError, match="OTX hostname is down"):
            connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original


class TestOutOfScope:
    @pytest.mark.parametrize("entity_type", ["Domain-Name", "Url", "IPv6-Addr"])
    def test_manual_out_of_scope_never_calls_otx(self, entity_type):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        result = connector.callback(_make_data(entity_type))

        assert result == f"Entity type {entity_type} is out of scope"
        processor.client.get_general.assert_not_called()
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

        processor.client.get_general.assert_not_called()
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_scope_is_checked_before_tlp(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)

        result = connector.callback(
            _make_data("IPv6-Addr", tlp="TLP:RED", playbook=True)
        )

        assert result == "Entity type IPv6-Addr is out of scope"
        processor.client.get_general.assert_not_called()


class TestMaxTlp:
    @pytest.mark.parametrize("tlp", ["TLP:RED", "TLP:AMBER+STRICT"])
    def test_manual_entity_above_max_tlp_never_calls_otx(self, tlp):
        helper = _make_helper()
        connector, processor = _make_connector(helper)

        result = connector.callback(_make_data(tlp=tlp))

        assert result == "Entity TLP is not allowed (max TLP: amber)"
        processor.client.get_general.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_entity_above_max_tlp_sends_the_original_bundle(self):
        helper = _make_helper(playbook=True)
        connector, processor = _make_connector(helper)
        data = _make_data(tlp="TLP:RED", playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        processor.client.get_general.assert_not_called()
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_a_lower_max_tlp_from_the_settings_is_applied(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings({"max_tlp": "TLP:GREEN"})
        )

        connector.callback(_make_data(tlp="TLP:AMBER"))

        processor.client.get_general.assert_not_called()

    def test_a_higher_max_tlp_from_the_settings_is_applied(self):
        helper = _make_helper()
        connector, processor = _make_connector(
            helper, _make_settings({"max_tlp": "TLP:RED"})
        )

        connector.callback(_make_data(tlp="TLP:RED"))

        processor.client.get_general.assert_called_once()
