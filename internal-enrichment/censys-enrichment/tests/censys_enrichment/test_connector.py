from unittest.mock import Mock

import pytest
from censys_enrichment.config import Config
from censys_enrichment.connector import (
    Connector,
    EntityNotInScopeError,
    EntityTypeNotSupportedError,
    MaxTlpError,
)


@pytest.mark.usefixtures("mock_config")
def test__send_bundle(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)
    res = connector._send_bundle([])
    mocked_helper.stix2_create_bundle.assert_called_once_with(items=[])
    mocked_helper.send_stix2_bundle.assert_called_once()
    assert res == "Sending 0 stix bundle(s) for worker import"


@pytest.mark.usefixtures("mock_config")
def test__is_entity_in_scope(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)
    assert connector._is_entity_in_scope("IPv4-Addr")
    assert not connector._is_entity_in_scope("IPv6-Addr")


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
    connector = Connector(config=Config(), helper=mocked_helper)
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
    connector = Connector(config=Config(), helper=mocked_helper)

    assert connector._is_entity_tlp_allowed(markings) == expected


@pytest.mark.usefixtures("mock_config")
def test__get_related_stix_objects(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)
    with pytest.raises(EntityTypeNotSupportedError) as exc_info:
        connector._generate_octi_objects({"entity_type": "IPv4-Addr"})

    assert exc_info.typename == "EntityTypeNotSupportedError"
    assert exc_info.value.args == ("Observable type IPv4-Addr not supported",)


@pytest.mark.usefixtures("mock_config")
def test__process(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)

    with pytest.raises(EntityNotInScopeError) as exc_info:
        connector._process([], {"entity_type": "IPv6-Addr"})
    assert exc_info.typename == "EntityNotInScopeError"
    assert exc_info.value.args == ("Unsupported entity type: IPv6-Addr",)

    with pytest.raises(MaxTlpError) as exc_info:
        connector._process(
            [],
            {
                "entity_type": "IPv4-Addr",
                "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
            },
        )
    assert exc_info.typename == "MaxTlpError"
    assert exc_info.value.args == (
        "TLP [{'definition_type': 'TLP', 'definition': 'TLP:RED'}] of observable exceeds MAX TLP",
    )

    with pytest.raises(EntityTypeNotSupportedError) as exc_info:
        connector._process(
            [],
            {
                "entity_type": "IPv4-Addr",
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:AMBER"}
                ],
            },
        )

    assert exc_info.typename == "EntityTypeNotSupportedError"
    assert exc_info.value.args == ("Observable type IPv4-Addr not supported",)


@pytest.mark.usefixtures("mock_config")
def test__message_callback(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)

    with pytest.raises(EntityTypeNotSupportedError) as exc_info:
        connector._message_callback(
            {
                "event_type": "INTERNAL_ENRICHMENT",
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
    assert exc_info.value.args == ("Observable type IPv4-Addr not supported",)


@pytest.mark.usefixtures("mock_config")
def test__message_callback_in_playbook(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)

    res = connector._message_callback(
        {
            "stix_objects": [],
            "enrichment_entity": {
                "entity_type": "IPv4-Addr",
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:AMBER"}
                ],
            },
        }
    )
    assert res == "Sending 0 stix bundle(s) for worker import"


@pytest.mark.usefixtures("mock_config")
def test_run(mocked_helper: Mock) -> None:
    connector = Connector(config=Config(), helper=mocked_helper)
    connector.run()

    mocked_helper.listen.assert_called_once_with(
        message_callback=connector._message_callback
    )
