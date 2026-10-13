import json
from typing import Any
from unittest.mock import Mock

import pytest
from censys_enrichmentapis.client import Client
from censys_enrichmentapis.connector import Connector
from censys_enrichmentapis.errors import (
    EntityNotInScopeError,
    EntityTypeNotSupportedError,
    MarkingResolutionError,
    MaxTlpError,
)
from censys_enrichmentapis.settings import ConfigLoader
from pytest_mock import MockerFixture


def filter_by_key_value(items: list[dict], key: str, value: Any) -> list[dict]:
    return [item for item in items if item.get(key) == value]


@pytest.mark.usefixtures("mock_config")
def test__send_bundle(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    res = connector._send_bundle([])
    mocked_helper.stix2_create_bundle.assert_called_once_with(items=[])
    mocked_helper.send_stix2_bundle.assert_called_once()
    assert res == "Sending 0 stix bundle(s) for worker import"


@pytest.mark.usefixtures("mock_config")
def test__is_entity_in_scope(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    assert connector._is_entity_in_scope("IPv4-Addr")
    assert not connector._is_entity_in_scope("NotInScope")


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "markings, expected_tlp",
    [
        ([], None),
        ([{"definition_type": "TLP", "definition": "TLP:AMBER"}], "TLP:AMBER"),
        ([{"definition_type": "PAP", "definition": "PAP:AMBER"}], None),
        (
            [
                {"definition_type": "TLP", "definition": "TLP:AMBER"},
                {"definition_type": "PAP", "definition": "PAP:AMBER"},
            ],
            "TLP:AMBER",
        ),
    ],
)
def test__extract_tlp(
    mocked_helper: Mock, markings: list[dict[str, str]], expected_tlp: str | None
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    assert connector._extract_tlp(markings) == expected_tlp


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "markings",
    [
        [],
        [{"definition_type": "TLP", "definition": "TLP:AMBER"}],
        [{"definition_type": "PAP", "definition": "PAP:AMBER"}],
    ],
)
def test__validate_entity_tlp_allows_accepted_markings(
    mocked_helper: Mock, markings: list[dict[str, str]]
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )

    assert connector._validate_entity_tlp(markings) is None


@pytest.mark.usefixtures("mock_config")
def test__validate_entity_tlp_rejects_excessive_tlp(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    markings = [{"definition_type": "TLP", "definition": "TLP:RED"}]

    with pytest.raises(MaxTlpError, match="exceeds MAX TLP"):
        connector._validate_entity_tlp(markings)


@pytest.mark.usefixtures("mock_config")
def test__generate_octi_objects_wrong_entity_type(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    with pytest.raises(EntityTypeNotSupportedError) as exc_info:
        connector._generate_octi_objects({"type": "wrong-type"})

    assert exc_info.typename == "EntityTypeNotSupportedError"
    assert exc_info.value.args == ("Observable type wrong-type not supported",)


@pytest.mark.usefixtures("mock_config")
def test__process_entity_not_in_scope_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )

    with pytest.raises(EntityNotInScopeError) as exc_info:
        connector._process(
            observable={"entity_type": "wrong-type"},
            stix_entity={},
            original_stix_objects=[],
        )
    assert exc_info.typename == "EntityNotInScopeError"
    assert exc_info.value.args == ("Unsupported entity type: wrong-type",)


@pytest.mark.usefixtures("mock_config")
def test__process_max_tlp_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )

    with pytest.raises(MaxTlpError) as exc_info:
        connector._process(
            observable={
                "entity_type": "IPv4-Addr",
                "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
            },
            stix_entity={},
            original_stix_objects=[],
        )
    assert exc_info.typename == "MaxTlpError"
    assert exc_info.value.args == (
        "TLP TLP:RED of observable exceeds MAX TLP TLP:AMBER",
    )


@pytest.mark.usefixtures("mock_config")
def test__process_entity_type_not_supported_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )

    with pytest.raises(EntityTypeNotSupportedError) as exc_info:
        connector._process(
            observable={
                "entity_type": "IPv4-Addr",
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:AMBER"}
                ],
            },
            stix_entity={"type": "wrong-type"},
            original_stix_objects=[],
        )

    assert exc_info.typename == "EntityTypeNotSupportedError"
    assert exc_info.value.args == ("Observable type wrong-type not supported",)


@pytest.mark.usefixtures("mock_config")
def test__process_propagates_source_marking_refs(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    marking_id = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    generate = mocker.patch.object(
        connector,
        "_generate_octi_objects",
        return_value=iter([]),
    )

    connector._process(
        observable={
            "entity_type": "IPv4-Addr",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": marking_id,
                }
            ],
        },
        stix_entity={"id": "ipv4-addr--example", "type": "ipv4-addr"},
        original_stix_objects=[],
    )

    assert generate.call_args.kwargs["marking_refs"] == [marking_id]


@pytest.mark.usefixtures("mock_config")
def test__process_includes_source_marking_definitions(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    tlp_id = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    pap_id = "marking-definition--a6f20d4d-0360-59b6-ba22-3b48707828b1"
    mocker.patch.object(connector, "_generate_octi_objects", return_value=iter([]))

    result = connector._process(
        observable={
            "entity_type": "IPv4-Addr",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": tlp_id,
                },
                {
                    "definition_type": "PAP",
                    "definition": "PAP:AMBER",
                    "standard_id": pap_id,
                },
            ],
        },
        stix_entity={
            "id": "ipv4-addr--example",
            "type": "ipv4-addr",
            "object_marking_refs": [tlp_id, pap_id],
        },
        original_stix_objects=[],
    )

    assert [definition["id"] for definition in result] == [tlp_id, pap_id]
    # Materialized exactly like pycti's ``prepare_export`` does for OpenCTI.
    assert result[0] == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": tlp_id,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    }
    assert result[1]["definition_type"] == "pap"
    assert result[1]["name"] == "PAP:AMBER"


@pytest.mark.usefixtures("mock_config")
def test__process_materializes_custom_marking_from_object_marking(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    # A custom (statement-like) marking known only through ``objectMarking``
    # must be materialized too, so derived objects keep the source marking.
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    custom_id = "marking-definition--22222222-2222-4222-8222-222222222222"
    generate = mocker.patch.object(
        connector, "_generate_octi_objects", return_value=iter([])
    )

    result = connector._process(
        observable={
            "entity_type": "IPv4-Addr",
            "objectMarking": [
                {
                    "definition_type": "statement",
                    "definition": "Internal use only",
                    "standard_id": custom_id,
                    "created": "2026-01-01T00:00:00.000Z",
                }
            ],
        },
        stix_entity={"id": "ipv4-addr--example", "type": "ipv4-addr"},
        original_stix_objects=[],
    )

    assert generate.call_args.kwargs["marking_refs"] == [custom_id]
    assert result == [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": custom_id,
            "created": "2026-01-01T00:00:00.000Z",
            "definition_type": "statement",
            "name": "Internal use only",
            "definition": {"statement": "internal use only"},
        }
    ]


@pytest.mark.usefixtures("mock_config")
def test__process_does_not_bundle_already_bundled_marking_definitions(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    tlp_id = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    bundled_definition = {"type": "marking-definition", "id": tlp_id}
    generate = mocker.patch.object(
        connector, "_generate_octi_objects", return_value=iter([])
    )

    result = connector._process(
        observable={
            "entity_type": "IPv4-Addr",
            "objectMarking": [
                {
                    "definition_type": "TLP",
                    "definition": "TLP:AMBER",
                    "standard_id": tlp_id,
                }
            ],
        },
        stix_entity={
            "id": "ipv4-addr--example",
            "type": "ipv4-addr",
            "object_marking_refs": [tlp_id],
        },
        original_stix_objects=[bundled_definition],
    )

    assert generate.call_args.kwargs["marking_refs"] == [tlp_id]
    assert result == [bundled_definition]


@pytest.mark.usefixtures("mock_config")
def test__process_refuses_unresolvable_marking_ref(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    # A source marking that is neither bundled nor described by
    # ``objectMarking`` must never be dropped (which would let the derived
    # objects fall back to TLP:CLEAR): the enrichment fails instead.
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    unknown_id = "marking-definition--11111111-1111-4111-8111-111111111111"
    generate = mocker.patch.object(
        connector, "_generate_octi_objects", return_value=iter([])
    )

    with pytest.raises(MarkingResolutionError, match=unknown_id):
        connector._process(
            observable={"entity_type": "IPv4-Addr", "objectMarking": []},
            stix_entity={
                "id": "ipv4-addr--example",
                "type": "ipv4-addr",
                "object_marking_refs": [unknown_id],
            },
            original_stix_objects=[],
        )

    generate.assert_not_called()


@pytest.mark.usefixtures("mock_config")
def test__process_unmarked_source_uses_default_marking(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    generate = mocker.patch.object(
        connector, "_generate_octi_objects", return_value=iter([])
    )

    result = connector._process(
        observable={"entity_type": "IPv4-Addr", "objectMarking": []},
        stix_entity={"id": "ipv4-addr--example", "type": "ipv4-addr"},
        original_stix_objects=[],
    )

    # No refs -> the builder falls back to the connector's TLP:CLEAR marking.
    assert generate.call_args.kwargs["marking_refs"] == []
    assert result == []


@pytest.mark.usefixtures("mock_config")
def test__process_keeps_unknown_marking_ref_present_in_input_bundle(
    mocked_helper: Mock, mocker: MockerFixture
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    unknown_id = "marking-definition--11111111-1111-4111-8111-111111111111"
    source_definition = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": unknown_id,
        "created": "2026-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "source restriction"},
    }
    generate = mocker.patch.object(
        connector, "_generate_octi_objects", return_value=iter([])
    )

    result = connector._process(
        observable={"entity_type": "IPv4-Addr", "objectMarking": []},
        stix_entity={
            "id": "ipv4-addr--example",
            "type": "ipv4-addr",
            "object_marking_refs": [unknown_id],
        },
        original_stix_objects=[source_definition],
    )

    assert generate.call_args.kwargs["marking_refs"] == [unknown_id]
    assert result == [source_definition]


@pytest.mark.usefixtures("mock_config")
def test__message_callback_entity_type_not_supported_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )

    with pytest.raises(EntityTypeNotSupportedError) as exc_info:
        connector._message_callback(
            {
                "event_type": "INTERNAL_ENRICHMENT",
                "stix_entity": {"type": "wrong-type"},
                "stix_objects": [],
                "enrichment_entity": {
                    "entity_type": "IPv4-Addr",
                    "objectMarking": [
                        {"definition_type": "TLP", "definition": "TLP:AMBER"}
                    ],
                },
            }
        )
    assert exc_info.typename == "EntityTypeNotSupportedError"
    assert exc_info.value.args == ("Observable type wrong-type not supported",)


@pytest.mark.usefixtures("mock_config")
def test__message_callback_in_playbook(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )

    res = connector._message_callback(
        {
            "stix_objects": [],
            "stix_entity": {"id": "ipv4-addr--example", "type": "ipv4-addr"},
            "enrichment_entity": {
                "entity_type": "wrong-type",
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:AMBER"}
                ],
            },
        }
    )
    assert res == "Sending 0 stix bundle(s) for worker import"
    # The failure is logged through a method pycti's logger actually exposes.
    mocked_helper.connector_logger.error.assert_called_once_with(
        "Error processing message",
        {"error": "Unsupported entity type: wrong-type"},
    )


@pytest.mark.usefixtures("mock_config")
def test__message_callback_not_in_playbook(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    with pytest.raises(KeyError) as exc_info:
        connector._message_callback(
            {
                "event_type": "INTERNAL_ENRICHMENT",  # Present => not in playbook
                "stix_objects": [],
                "enrichment_entity": {
                    "entity_type": "wrong-type",
                    "objectMarking": [
                        {"definition_type": "TLP", "definition": "TLP:AMBER"}
                    ],
                },
            }
        )
    assert exc_info.typename == "KeyError"
    assert exc_info.value.args == ("stix_entity",)


@pytest.mark.usefixtures("mock_config")
def test_run(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
    )
    connector.run()

    mocked_helper.listen.assert_called_once_with(
        message_callback=connector._message_callback
    )


@pytest.mark.usefixtures("mock_config")
def test_enrichment(mocked_helper: Mock, get_host, ipv4_enrichment_message):
    client = Client(
        organisation_id="test-org-id",
        token="test-token",
    )
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=client,
    )
    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    existing_labels = ipv4_enrichment_message["stix_objects"][0][
        "x_opencti_labels"
    ].copy()
    connector._message_callback(ipv4_enrichment_message)

    primary_observable = next(
        stix_object
        for stix_object in sent_bundle["objects"]
        if stix_object["id"] == ipv4_enrichment_message["stix_entity"]["id"]
    )
    assert primary_observable["x_opencti_labels"] == [
        *existing_labels,
        "Censys_BULLETPROOF",
        "Censys_REMOTE_ACCESS",
    ]

    city_name = filter_by_key_value(
        sent_bundle["objects"], "x_opencti_location_type", "City"
    )[0]["name"]
    assert city_name == get_host.location.city
    region_name = filter_by_key_value(
        sent_bundle["objects"], "x_opencti_location_type", "Region"
    )[0]["name"]
    assert region_name == get_host.location.continent
    administrative_area_name = filter_by_key_value(
        sent_bundle["objects"], "x_opencti_location_type", "Administrative-Area"
    )[0]["name"]
    assert administrative_area_name == get_host.location.province
    country_name = filter_by_key_value(
        sent_bundle["objects"], "x_opencti_location_type", "Country"
    )
    assert country_name[0]["name"] == get_host.location.country

    hostnames = filter_by_key_value(sent_bundle["objects"], "type", "hostname")
    for url in get_host.dns.names:
        assert any(hostname_obj["value"] == url for hostname_obj in hostnames)

    autonomous_system = filter_by_key_value(
        sent_bundle["objects"], "type", "autonomous-system"
    )[0]
    assert autonomous_system["number"] == get_host.autonomous_system.asn
    assert autonomous_system["name"] == get_host.autonomous_system.name
    assert (
        autonomous_system["x_opencti_description"]
        == get_host.autonomous_system.description
    )


@pytest.mark.usefixtures("mock_config")
def test_domain_name_enrichment(
    mocker: MockerFixture, mocked_helper: Mock, domain_name_enrichment_message
):
    web_properties = [
        {
            "hostname": "example.com",
            "port": 80,
            "scan_time": "2026-09-17T12:00:00Z",
            "labels": [{"value": "WEB"}],
        },
        {
            "hostname": "example.com",
            "port": 443,
            "scan_time": "2026-09-17T12:01:00Z",
            "threats": [{"name": "Fake Captcha"}],
        },
    ]
    mock_fetch_web_properties = mocker.patch(
        "censys_enrichmentapis.client.Client.fetch_web_properties",
        return_value=web_properties,
    )
    mocker.patch(
        "censys_enrichmentapis.client.Client.fetch_certs_by_domain", return_value=[]
    )
    client = Client(
        organisation_id="test-org-id",
        token="test-token",
    )
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=client,
    )
    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._message_callback(domain_name_enrichment_message)
    mock_fetch_web_properties.assert_called_once_with(
        domain_name_enrichment_message["stix_entity"]["value"], ports=(80, 443)
    )

    notes = filter_by_key_value(sent_bundle["objects"], "type", "note")
    assert {note["abstract"] for note in notes} == {
        "Censys web property `example.com`:80",
        "Censys web property `example.com`:443",
    }
    assert any("| web.labels.value | `WEB` |" in note["content"] for note in notes)
    assert any(
        "| web.threats.name | `Fake Captcha` |" in note["content"] for note in notes
    )
    assert any(
        note["content"].startswith(
            "[https://platform.censys.io/web/example.com:80]"
            "(https://platform.censys.io/web/example.com:80)"
        )
        for note in notes
    )

    domain = next(
        object_
        for object_ in sent_bundle["objects"]
        if object_["id"] == domain_name_enrichment_message["stix_entity"]["id"]
    )
    assert "Censys_Threat_Fake_Captcha" in domain["x_opencti_labels"]

    threat_note = next(
        note
        for note in notes
        if note["abstract"] == "Censys web property `example.com`:443"
    )
    assert threat_note["labels"] == ["Censys_Threat_Fake_Captcha"]
