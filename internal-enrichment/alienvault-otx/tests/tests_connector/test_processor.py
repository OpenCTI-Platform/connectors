import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call

import pytest
from connector import AlienVaultOtxProcessor, ConnectorSettings
from connector.processor import OtxLookup
from connectors_sdk import EnrichmentMessage
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import URL, DomainName, IPV4Address
from otx_client import OtxClient, OtxGeneral
from pycti import Identity

RESOURCES = Path(__file__).parent.parent / "resources"
OCTI_ID = "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c"
SUBDOMAIN = "www.malicious.example"

# Entity type, SDK model, observable value, OTX section, OTX page URL of the value, fixture
CASES = {
    "IPv4-Addr": (
        IPV4Address,
        "192.0.2.10",
        "IPv4",
        "https://otx.alienvault.com/indicator/ip/192.0.2.10",
        "general_ipv4_known.json",
    ),
    "Domain-Name": (
        DomainName,
        "malicious.example",
        "domain",
        "https://otx.alienvault.com/indicator/domain/malicious.example",
        "general_domain_known.json",
    ),
    "Url": (
        URL,
        "http://malicious.example/payload.bin?id=1",
        "url",
        "https://otx.alienvault.com/indicator/url/"
        "http%3A%2F%2Fmalicious.example%2Fpayload.bin%3Fid%3D1",
        "general_url_known.json",
    ),
}


def load_general(name: str) -> OtxGeneral:
    return OtxGeneral.model_validate_json((RESOURCES / name).read_text())


def _make_settings() -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "alienvault_otx": {"api_key": "test-api-key"},
                }
            )

    return FakeConnectorSettings()


def _make_processor() -> AlienVaultOtxProcessor:
    """A processor wired as the connector does, with a mocked OTX client."""
    processor = AlienVaultOtxProcessor()
    processor.inject_dependencies(settings=_make_settings())
    processor.post_init()
    processor.client = MagicMock(spec=OtxClient)
    return processor


def _make_message(
    entity_type: str = "IPv4-Addr", value: str | None = None
) -> EnrichmentMessage:
    model, default_value, *_ = CASES[entity_type]
    value = value or default_value
    stix_entity = {
        "type": entity_type.lower(),
        "id": model(value=value).to_stix2_object().id,
        "value": value,
    }
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {"id": OCTI_ID, "entity_type": entity_type},
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
            "from_playbook": False,
        }
    )


def _stix(objects: list[Any]) -> list[dict[str, Any]]:
    return [json.loads(obj.to_stix2_object().serialize()) for obj in objects]


def test_processor_declares_the_handled_entity_types():
    assert AlienVaultOtxProcessor.handled_entity_types == frozenset(
        {"IPv4-Addr", "Domain-Name", "Url"}
    )


@pytest.mark.parametrize(
    "entity_type, expected",
    [
        ("IPv4-Addr", True),
        ("ipv4-addr", True),
        ("Domain-Name", True),
        ("Url", True),
        ("IPv6-Addr", False),
        ("StixFile", False),
    ],
)
def test_processor_can_process_only_handled_entity_types(entity_type, expected):
    processor = AlienVaultOtxProcessor()

    assert processor.can_process(_make_message_of_type(entity_type)) is expected


def _make_message_of_type(entity_type: str) -> EnrichmentMessage:
    stix_entity = {"type": entity_type.lower(), "id": f"{entity_type.lower()}--x"}
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {"id": OCTI_ID, "entity_type": entity_type},
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
            "from_playbook": False,
        }
    )


class TestPostInit:
    def test_builds_the_client_from_the_settings(self):
        processor = AlienVaultOtxProcessor()
        processor.inject_dependencies(settings=_make_settings())

        processor.post_init()

        assert isinstance(processor.client, OtxClient)
        assert processor.client.session_headers == {"X-OTX-API-KEY": "test-api-key"}

    def test_author_is_the_one_of_the_alienvault_external_import(self):
        processor = _make_processor()

        author = processor.author.to_stix2_object()

        assert author.name == "AlienVault"
        assert author.identity_class == "organization"
        assert author.id == Identity.generate_id("AlienVault", "organization")

    def test_marking_is_tlp_clear(self):
        processor = _make_processor()

        marking = processor.tlp_marking.to_stix2_object()

        assert marking["x_opencti_definition"] == "TLP:CLEAR"


class TestCollect:
    @pytest.mark.parametrize("entity_type", list(CASES))
    def test_fetches_the_general_section_of_the_entity_value(self, entity_type):
        _, value, section, _, fixture = CASES[entity_type]
        processor = _make_processor()
        general = load_general(fixture)
        processor.client.get_general.return_value = general

        result = processor.collect(_make_message(entity_type))

        assert isinstance(result, OtxLookup)
        assert result.section == section
        assert result.general is general
        processor.client.get_general.assert_called_once_with(section, value)

    @pytest.mark.parametrize("entity_type", list(CASES))
    def test_returns_none_when_otx_does_not_have_the_indicator(self, entity_type):
        processor = _make_processor()
        processor.client.get_general.return_value = None

        assert processor.collect(_make_message(entity_type)) is None
        # No fallback after a 400 or a 404
        processor.client.get_general.assert_called_once()

    @pytest.mark.parametrize("entity_type", ["IPv4-Addr", "Url"])
    def test_no_fallback_for_an_unknown_ipv4_or_url(self, entity_type):
        processor = _make_processor()
        processor.client.get_general.return_value = load_general(
            "general_ipv4_unknown.json"
        )

        result = processor.collect(_make_message(entity_type))

        assert result.general.pulse_info.count == 0
        processor.client.get_general.assert_called_once()

    def test_known_domain_does_not_query_hostname(self):
        processor = _make_processor()
        general = load_general("general_domain_known.json")
        processor.client.get_general.return_value = general

        result = processor.collect(_make_message("Domain-Name"))

        assert result == OtxLookup("domain", "domain", general)
        assert result.section == "domain"
        processor.client.get_general.assert_called_once_with(
            "domain", "malicious.example"
        )

    def test_domain_without_pulse_falls_back_on_hostname(self):
        processor = _make_processor()
        domain = load_general("general_domain_unknown.json")
        hostname = load_general("general_hostname_known.json")
        processor.client.get_general.side_effect = [domain, hostname]

        result = processor.collect(_make_message("Domain-Name", SUBDOMAIN))

        assert result == OtxLookup("hostname", "hostname", hostname)
        assert result.section == "hostname"
        assert processor.client.get_general.call_args_list == [
            call("domain", SUBDOMAIN),
            call("hostname", SUBDOMAIN),
        ]

    def test_domain_without_pulse_in_both_sections_gives_no_pulse(self):
        processor = _make_processor()
        domain = load_general("general_domain_unknown.json")
        processor.client.get_general.side_effect = [domain, domain]

        result = processor.collect(_make_message("Domain-Name", SUBDOMAIN))

        assert result.general.pulse_info.count == 0
        assert processor.client.get_general.call_count == 2

    def test_hostname_rejected_by_otx_keeps_the_domain_answer(self):
        processor = _make_processor()
        domain = load_general("general_domain_unknown.json")
        processor.client.get_general.side_effect = [domain, None]

        result = processor.collect(_make_message("Domain-Name", SUBDOMAIN))

        assert result == OtxLookup("domain", "domain", domain)
        assert result.section == "domain"

    def test_domain_rejected_by_otx_does_not_query_hostname(self):
        processor = _make_processor()
        processor.client.get_general.return_value = None

        assert processor.collect(_make_message("Domain-Name", SUBDOMAIN)) is None
        processor.client.get_general.assert_called_once_with("domain", SUBDOMAIN)

    def test_lets_the_fallback_error_through_unwrapped(self):
        processor = _make_processor()
        error = DataRetrievalError("Failed to fetch the OTX hostname")
        processor.client.get_general.side_effect = [
            load_general("general_domain_unknown.json"),
            error,
        ]

        with pytest.raises(DataRetrievalError) as err:
            processor.collect(_make_message("Domain-Name", SUBDOMAIN))

        assert err.value is error

    def test_lets_the_client_error_through_unwrapped(self):
        processor = _make_processor()
        error = DataRetrievalError("Failed to fetch the OTX IPv4 192.0.2.10")
        processor.client.get_general.side_effect = error

        with pytest.raises(DataRetrievalError) as err:
            processor.collect(_make_message())

        assert err.value is error

    def test_logs_the_lookup_at_debug_with_the_message_context(
        self, caplog: pytest.LogCaptureFixture
    ):
        caplog.set_level(logging.DEBUG)
        processor = _make_processor()
        processor.client.get_general.return_value = None

        processor.collect(_make_message())

        assert [
            getattr(record, "attributes", None)
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and record.getMessage() == "Fetching the OTX general section"
        ] == [
            {
                "octi_id": OCTI_ID,
                "octi_entity_type": "IPv4-Addr",
                "from_playbook": False,
                "section": "IPv4",
            }
        ]

    def test_logs_the_hostname_fallback_at_debug_with_its_section(
        self, caplog: pytest.LogCaptureFixture
    ):
        caplog.set_level(logging.DEBUG)
        processor = _make_processor()
        processor.client.get_general.side_effect = [
            load_general("general_domain_unknown.json"),
            load_general("general_hostname_known.json"),
        ]

        processor.collect(_make_message("Domain-Name", SUBDOMAIN))

        assert [
            getattr(record, "attributes", None)
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and record.getMessage()
            == "Domain unknown to OTX, looking it up as a hostname"
        ] == [
            {
                "octi_id": OCTI_ID,
                "octi_entity_type": "Domain-Name",
                "from_playbook": False,
                "section": "hostname",
            }
        ]

    def test_negative_pulse_count_is_unknown_and_falls_back_on_hostname(self):
        processor = _make_processor()
        domain = OtxGeneral.model_validate({"pulse_info": {"count": -1}})
        hostname = load_general("general_hostname_known.json")
        processor.client.get_general.side_effect = [domain, hostname]

        result = processor.collect(_make_message("Domain-Name", SUBDOMAIN))

        assert result == OtxLookup("hostname", "hostname", hostname)
        assert result.section == "hostname"
        assert processor.client.get_general.call_count == 2


def _lookup(fixture: str, entity_type: str | None = None) -> OtxLookup:
    """The lookup of a fixture, on the section and page of the entity type.

    Without an entity type, the lookup is the one of the `hostname` section.
    """
    section = CASES[entity_type][2] if entity_type else "hostname"
    page_url = CASES[entity_type][3] if entity_type else "/indicator/hostname/"
    page_path = page_url.split("/indicator/")[1].split("/")[0]
    return OtxLookup(section, page_path, load_general(fixture))


class TestTransform:
    @pytest.mark.parametrize("entity_type", list(CASES))
    def test_known_indicator_gives_author_marking_and_observable(self, entity_type):
        model, _, _, _, fixture = CASES[entity_type]
        processor = _make_processor()

        result = processor.transform(
            _lookup(fixture, entity_type), _make_message(entity_type)
        )

        assert len(result) == 3
        assert result[0] is processor.author
        assert result[1] is processor.tlp_marking
        assert isinstance(result[2], model)

    @pytest.mark.parametrize("entity_type", list(CASES))
    def test_observable_has_the_id_of_the_entity_and_the_otx_reference(
        self, entity_type
    ):
        _, value, _, page_url, fixture = CASES[entity_type]
        processor = _make_processor()
        message = _make_message(entity_type)

        observable = processor.transform(_lookup(fixture, entity_type), message)[2]

        stix = json.loads(observable.to_stix2_object().serialize())
        assert stix["id"] == message.stix_entity.id
        assert stix["value"] == value
        assert stix["extensions"][next(iter(stix["extensions"]))][
            "external_references"
        ] == [{"source_name": "AlienVault OTX", "url": page_url}]

    def test_domain_known_through_hostname_links_to_the_hostname_page(self):
        processor = _make_processor()
        message = _make_message("Domain-Name", SUBDOMAIN)

        observable = processor.transform(
            _lookup("general_hostname_known.json"), message
        )[2]

        stix = json.loads(observable.to_stix2_object().serialize())
        assert stix["value"] == SUBDOMAIN
        assert stix["extensions"][next(iter(stix["extensions"]))][
            "external_references"
        ] == [
            {
                "source_name": "AlienVault OTX",
                "url": f"https://otx.alienvault.com/indicator/hostname/{SUBDOMAIN}",
            }
        ]

    def test_hostname_answer_without_pulse_gives_nothing(self):
        processor = _make_processor()
        lookup = OtxLookup(
            "hostname", "hostname", load_general("general_domain_unknown.json")
        )

        assert processor.transform(lookup, _make_message("Domain-Name")) == []

    def test_transform_makes_no_network_call(self):
        processor = _make_processor()

        processor.transform(_lookup("general_hostname_known.json"), _make_message())

        assert processor.client.mock_calls == []

    def test_observable_leaves_the_author_and_markings_of_the_entity_untouched(self):
        processor = _make_processor()

        observable = processor.transform(
            _lookup("general_ipv4_known.json", "IPv4-Addr"), _make_message()
        )[2]

        stix = json.loads(observable.to_stix2_object().serialize())
        assert "object_marking_refs" not in stix
        assert "created_by_ref" not in json.dumps(stix)

    def test_unknown_indicator_gives_nothing(self):
        processor = _make_processor()
        lookup = _lookup("general_ipv4_unknown.json", "IPv4-Addr")
        assert lookup.general.pulse_info.count == 0

        assert processor.transform(lookup, _make_message()) == []

    def test_negative_pulse_count_gives_nothing(self):
        processor = _make_processor()
        lookup = OtxLookup(
            "IPv4", "ip", OtxGeneral.model_validate({"pulse_info": {"count": -1}})
        )

        assert processor.transform(lookup, _make_message()) == []

    def test_no_data_gives_nothing(self):
        assert _make_processor().transform(None, _make_message()) == []

    def test_every_reference_of_the_result_resolves_in_the_bundle(self):
        processor = _make_processor()
        message = _make_message("Url")

        result = processor.transform(_lookup("general_url_known.json", "Url"), message)

        objects = _stix(result)
        ids = {obj["id"] for obj in objects}
        assert len(ids) == len(objects)
        assert objects[0]["id"] == Identity.generate_id("AlienVault", "organization")
        refs = [
            ref
            for obj in objects
            for key, value in obj.items()
            if key.endswith(("_ref", "_refs"))
            for ref in (value if isinstance(value, list) else [value])
        ]
        assert all(ref in ids for ref in refs)


class TestProcess:
    def test_known_indicator_gives_author_marking_and_observable(self):
        processor = _make_processor()
        processor.client.get_general.return_value = load_general(
            "general_ipv4_known.json"
        )

        result = processor.process(_make_message())

        assert result[:2] == [processor.author, processor.tlp_marking]
        assert len(result) == 3

    def test_subdomain_known_only_in_hostname_gives_the_enriched_observable(self):
        processor = _make_processor()
        processor.client.get_general.side_effect = [
            load_general("general_domain_unknown.json"),
            load_general("general_hostname_known.json"),
        ]

        result = processor.process(_make_message("Domain-Name", SUBDOMAIN))

        assert len(result) == 3
        assert isinstance(result[2], DomainName)

    def test_subdomain_unknown_in_both_sections_gives_nothing(self):
        processor = _make_processor()
        processor.client.get_general.return_value = load_general(
            "general_domain_unknown.json"
        )

        assert processor.process(_make_message("Domain-Name", SUBDOMAIN)) == []
        assert processor.client.get_general.call_count == 2

    @pytest.mark.parametrize(
        "general", [None, load_general("general_ipv4_unknown.json")]
    )
    def test_unknown_indicator_gives_nothing(self, general):
        processor = _make_processor()
        processor.client.get_general.return_value = general

        assert processor.process(_make_message()) == []
