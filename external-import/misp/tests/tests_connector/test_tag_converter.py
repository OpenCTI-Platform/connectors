import pytest
from api_client.models import TagItem
from connector.use_cases.common import ConverterConfig
from connector.use_cases.convert_tag import TagConverter


@pytest.mark.parametrize(
    "original_tags_to_keep_as_labels, tag_name, expected",
    [
        # GIVEN no prefixes, WHEN tag is generic, THEN label is tag name
        ([], "sometag", "sometag"),
        # GIVEN prefix configured, WHEN tag starts with prefix, THEN label is tag name
        (["keepme"], "keepme:foo", "keepme:foo"),
        # GIVEN prefix configured, WHEN tag does not start with prefix, THEN label is extracted value
        (["keepme"], "other:foo", "foo"),
        # GIVEN no prefixes, WHEN tag is marking, THEN label is None
        ([], "tlp:amber", None),
        # GIVEN no prefixes, WHEN tag is entity, THEN label is None
        ([], 'misp-galaxy:threat-actor=APT28"', None),
        # GIVEN no prefixes, WHEN tag is in equal-quote format, THEN label is extracted value
        ([], 'foo="bar"', "bar"),
        # GIVEN no prefixes, WHEN tag is in colon format, THEN label is extracted value
        ([], "foo:bar", "bar"),
        # GIVEN no prefixes, WHEN tag is in digit format, THEN label is extracted value
        ([], "foo:123", "123"),
        # GIVEN marking prefix configured, WHEN tag is marking, THEN label is tag name
        (["tlp:"], "tlp:amber", "tlp:amber"),
        # GIVEN entity prefix configured, WHEN tag is entity, THEN label is tag name
        (
            ["misp-galaxy:threat-actor"],
            'misp-galaxy:threat-actor=APT28"',
            'misp-galaxy:threat-actor=APT28"',
        ),
    ],
)
def test_create_label_parametrized(original_tags_to_keep_as_labels, tag_name, expected):
    # GIVEN a TagConverter with the specified config
    config = ConverterConfig(
        external_reference_base_url="http://dummy",
        original_tags_to_keep_as_labels=original_tags_to_keep_as_labels,
    )
    converter = TagConverter(config)
    tag = TagItem(name=tag_name)

    # WHEN create_label is called
    result = converter.create_label(tag)

    # THEN the result matches expected
    assert result == expected
