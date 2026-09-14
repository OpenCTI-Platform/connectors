import json
from typing import Any
from unittest.mock import Mock

import pytest
from censys_enrichment.client import Client
from censys_enrichment.connector import (
    Connector,
    EntityNotInScopeError,
    EntityTypeNotSupportedError,
    MaxTlpError,
)
from censys_enrichment.converter import Converter
from censys_enrichment.settings import ConfigLoader


def filter_by_key_value(items: list[dict], key: str, value: Any) -> list[dict]:
    return [item for item in items if item.get(key) == value]


@pytest.mark.usefixtures("mock_config")
def test__send_bundle(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
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
        converter=Converter(),
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
        converter=Converter(),
    )
    assert connector._extract_tlp(markings) == expected_tlp


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "markings, expected",
    [
        ([], True),
        ([{"definition_type": "TLP", "definition": "TLP:AMBER"}], True),
        ([{"definition_type": "TLP", "definition": "TLP:RED"}], False),
        ([{"definition_type": "PAP", "definition": "PAP:AMBER"}], True),
    ],
)
def test__is_entity_tlp_allowed(
    mocked_helper: Mock, markings: list[dict[str, str]], expected: bool
) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
    )

    assert connector._is_entity_tlp_allowed(markings) == expected


@pytest.mark.usefixtures("mock_config")
def test__generate_octi_objects_wrong_entity_type(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
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
        converter=Converter(),
    )

    with pytest.raises(EntityNotInScopeError) as exc_info:
        connector._process(
            observable={"entity_type": "wrong-type"},
            stix_entity={},
            original_stix_objects=[],
        )
    assert exc_info.typename == "EntityNotInScopeError"
    assert exc_info.value.args == ("Unsupported entity type: wrong-type",)

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
        "TLP [{'definition_type': 'TLP', 'definition': 'TLP:RED'}] of observable exceeds MAX TLP",
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
def test__process_max_tlp_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
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
        "TLP [{'definition_type': 'TLP', 'definition': 'TLP:RED'}] of observable exceeds MAX TLP",
    )


@pytest.mark.usefixtures("mock_config")
def test__process_entity_type_not_supported_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
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
def test__message_callback_entity_type_not_supported_error(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
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
        converter=Converter(),
    )

    res = connector._message_callback(
        {
            "stix_objects": [],
            "enrichment_entity": {
                "entity_type": "wrong-type",
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:AMBER"}
                ],
            },
        }
    )
    assert res == "Sending 0 stix bundle(s) for worker import"


@pytest.mark.usefixtures("mock_config")
def test__message_callback_not_in_playbook(mocked_helper: Mock) -> None:
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=Mock(),
        converter=Converter(),
    )
    with pytest.raises(KeyError) as exc_info:
        connector._message_callback(
            {
                "event_type": "INTERNAL_ENRICHMENT",  # Mean not in playbook
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
        converter=Converter(),
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
        converter=Converter(),
    )
    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._message_callback(ipv4_enrichment_message)

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

    softwares = filter_by_key_value(sent_bundle["objects"], "type", "software")

    host_softwares = [service.software[0] for service in get_host.services]
    for host_software in host_softwares:
        assert any(
            software_obj["name"] == host_software.product
            and software_obj["vendor"] == host_software.vendor
            and software_obj["cpe"] == host_software.cpe
            for software_obj in softwares
        )

    autonomous_system = filter_by_key_value(
        sent_bundle["objects"], "type", "autonomous-system"
    )[0]
    assert autonomous_system["number"] == get_host.autonomous_system.asn
    assert autonomous_system["name"] == get_host.autonomous_system.name
    assert (
        autonomous_system["x_opencti_description"]
        == get_host.autonomous_system.description
    )

    sent_certs = filter_by_key_value(sent_bundle["objects"], "type", "x509-certificate")
    certs = [service.cert for service in get_host.services]
    for cert in certs:
        assert any(
            sent_cert["hashes"]["MD5"] == cert.fingerprint_md5
            and sent_cert["hashes"]["SHA-1"] == cert.fingerprint_sha1
            and sent_cert["hashes"]["SHA-256"] == cert.fingerprint_sha256
            for sent_cert in sent_certs
        )


@pytest.mark.usefixtures("mock_config")
def test_domain_name_enrichment(
    mocked_helper: Mock, fetch_hosts, domain_name_enrichment_message
):
    client = Client(
        organisation_id="test-org-id",
        token="test-token",
    )
    connector = Connector(
        config=ConfigLoader(),
        helper=mocked_helper,
        client=client,
        converter=Converter(),
    )
    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._message_callback(domain_name_enrichment_message)

    for host in fetch_hosts:
        ipv4_addresses = [
            addr["value"]
            for addr in filter_by_key_value(sent_bundle["objects"], "type", "ipv4-addr")
        ]
        assert host.ip in ipv4_addresses
        city_names = [
            city["name"]
            for city in filter_by_key_value(
                sent_bundle["objects"], "x_opencti_location_type", "City"
            )
        ]
        assert host.location.city in city_names
        region_names = [
            region["name"]
            for region in filter_by_key_value(
                sent_bundle["objects"], "x_opencti_location_type", "Region"
            )
        ]
        assert host.location.continent in region_names
        administrative_area_names = [
            area["name"]
            for area in filter_by_key_value(
                sent_bundle["objects"], "x_opencti_location_type", "Administrative-Area"
            )
        ]
        assert host.location.province in administrative_area_names
        country_names = [
            country["name"]
            for country in filter_by_key_value(
                sent_bundle["objects"], "x_opencti_location_type", "Country"
            )
        ]
        assert host.location.country in country_names

        hostnames = filter_by_key_value(sent_bundle["objects"], "type", "hostname")
        for url in host.dns.names:
            assert any(hostname_obj["value"] == url for hostname_obj in hostnames)

        softwares = filter_by_key_value(sent_bundle["objects"], "type", "software")

        host_softwares = [service.software[0] for service in host.services]
        for host_software in host_softwares:
            assert any(
                software_obj["name"] == host_software.product
                and software_obj["vendor"] == host_software.vendor
                and software_obj["cpe"] == host_software.cpe
                for software_obj in softwares
            )

        autonomous_system_numbers = [
            asys["number"]
            for asys in filter_by_key_value(
                sent_bundle["objects"], "type", "autonomous-system"
            )
        ]
        assert host.autonomous_system.asn in autonomous_system_numbers
        autonomous_system_names = [
            asys["name"]
            for asys in filter_by_key_value(
                sent_bundle["objects"], "type", "autonomous-system"
            )
        ]
        assert host.autonomous_system.name in autonomous_system_names
        autonomous_system_descriptions = [
            asys["x_opencti_description"]
            for asys in filter_by_key_value(
                sent_bundle["objects"], "type", "autonomous-system"
            )
        ]
        assert host.autonomous_system.description in autonomous_system_descriptions

        sent_certs = filter_by_key_value(
            sent_bundle["objects"], "type", "x509-certificate"
        )
        certs = [service.cert for service in host.services]
        for cert in certs:
            assert any(
                sent_cert["hashes"]["MD5"] == cert.fingerprint_md5
                and sent_cert["hashes"]["SHA-1"] == cert.fingerprint_sha1
                and sent_cert["hashes"]["SHA-256"] == cert.fingerprint_sha256
                for sent_cert in sent_certs
            )
